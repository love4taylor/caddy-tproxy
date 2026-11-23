package session

import (
	"container/list"
	"errors"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/frame"
)

var (
	ErrAuthentication = errors.New("relay credential rejected")
	ErrBackpressure   = errors.New("relay queue has insufficient space")
	ErrLimit          = errors.New("relay capacity exhausted")
	ErrProtocol       = errors.New("invalid relay frame or sequence")
	ErrConcurrent     = errors.New("carrier already in use")
	ErrClosed         = errors.New("relay session has ended")
)

type CreateResult struct {
	Token   string
	Welcome []byte
	Session *Session
}

type Metrics struct {
	SessionsCreated     uint64
	SessionsClosed      uint64
	StreamsOpened       uint64
	StreamsRejected     uint64
	BackendDialFailures uint64
	BytesUp             uint64
	BytesDown           uint64
	LimitHits           uint64
}

type Capacity struct {
	Sessions             int
	Streams              int
	BackendDialsInFlight int
	PendingBytes         int64
	PendingItems         int64
}

type managerMetrics struct {
	created, closed, opened, rejected, dialFailures, up, down, limited atomic.Uint64
}

type ticket struct {
	id             [32]byte
	origin         string
	owner          *profileQuota
	deadline       time.Time
	expiry, unused *list.Element
	result         CreateResult
}

type retiredToken struct {
	id       [32]byte
	deadline time.Time
}

type registration struct {
	key       [32]byte
	ticketKey [32]byte
	address   string
	profile   *profileQuota
}

type profileQuota struct {
	profile                     *config.Profile
	sessions, streams, dialling int
	newSessions, newStreams     bucket
}

type bucket struct {
	at        time.Time
	remaining float64
}

func (current bucket) consume(now time.Time, perMinute, burst int) (bucket, bool) {
	if current.at.IsZero() {
		current = bucket{at: now, remaining: float64(burst)}
	} else if now.After(current.at) {
		elapsed := now.Sub(current.at).Seconds()
		current = bucket{at: now, remaining: min(float64(burst), current.remaining+elapsed*float64(perMinute)/60)}
	}
	if current.remaining < 1 {
		return current, false
	}
	current.remaining--
	return current, true
}

// Manager owns authentication state and admission limits. Queue accounting is
// independent so data-plane traffic does not serialize credential lookups.
// Neither lock may be held while calling into a Session.
type Manager struct {
	config   config.Config
	tokens   tokenCodec
	profiles map[[32]byte]*profileQuota

	mu                                  sync.RWMutex
	stopping                            bool
	tickets                             map[[32]byte]*ticket
	ticketExpiry, unusedTickets         list.List
	ticketsPerAddress                   map[string]int
	retired                             map[[32]byte]*list.Element
	retiredOrder                        list.List
	sessions                            map[[32]byte]*Session
	registrations                       map[*Session]registration
	sessionsPerAddress                  map[string]int
	newTickets, newSessions, newStreams bucket
	streams, dialling, sockets          int

	budgetMu                              sync.Mutex
	pendingLimits                         pendingLimits
	pendingGlobalCost, pendingGlobalItems int64
	budgetChanged                         chan struct{}

	counters     managerMetrics
	shutdown     sync.Once
	drained      sync.WaitGroup
	stop, reaped chan struct{}
}

func NewManager(value config.Config, tokenKey [32]byte) *Manager {
	value.Profiles = slices.Clone(value.Profiles)
	m := &Manager{
		config: value, tokens: newTokenCodec(tokenKey), profiles: make(map[[32]byte]*profileQuota, len(value.Profiles)),
		tickets: make(map[[32]byte]*ticket), ticketsPerAddress: make(map[string]int),
		retired: make(map[[32]byte]*list.Element), sessions: make(map[[32]byte]*Session),
		registrations: make(map[*Session]registration), sessionsPerAddress: make(map[string]int),
		stop: make(chan struct{}), reaped: make(chan struct{}),
		pendingLimits: globalPendingLimits(value.Limits),
	}
	for i := range m.config.Profiles {
		profile := &m.config.Profiles[i]
		profile.CarrierMode = profile.CarrierMode.WithDefault()
		profile.Limits = profile.Limits.WithDefaults(value.Limits)
		m.profiles[profile.Capability] = &profileQuota{profile: profile}
	}
	go m.expire()
	return m
}

func (m *Manager) ContainsCapability(value []byte) bool {
	return len(value) == 32 && m.profiles[[32]byte(value)] != nil
}

func (m *Manager) MatchCapability(value []byte) *config.Profile {
	if len(value) == 32 {
		if entry := m.profiles[[32]byte(value)]; entry != nil {
			return entry.profile
		}
	}
	return nil
}

func (m *Manager) IssueBootstrap(profile *config.Profile, address string) (string, error) {
	if profile == nil || m.profiles[profile.Capability] == nil {
		return "", ErrAuthentication
	}
	owner := m.profiles[profile.Capability]
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return "", ErrClosed
	}
	now := time.Now()
	m.removeExpiredBootstrapsLocked(now)
	limit := m.config.Limits
	spent, allowed := m.newTickets.consume(now, limit.NewBootstrapsPerMinute, limit.NewBootstrapsBurst)
	if !allowed || (limit.MaxBootstrapsPerIP > 0 && m.ticketsPerAddress[address] >= limit.MaxBootstrapsPerIP) {
		m.counters.limited.Add(1)
		return "", ErrLimit
	}
	victim := m.unusedTickets.Front()
	if len(m.tickets) >= limit.MaxBootstrapsGlobal && victim == nil {
		m.counters.limited.Add(1)
		return "", ErrLimit
	}
	text, id, err := m.tokens.issue(TokenBootstrap)
	if err != nil {
		return "", err
	}
	if m.tickets[id] != nil {
		return "", ErrLimit
	}
	if len(m.tickets) >= limit.MaxBootstrapsGlobal {
		m.deleteTicket(victim.Value.(*ticket))
	}
	m.newTickets = spent
	v := &ticket{id: id, origin: address, owner: owner, deadline: now.Add(m.config.Timeouts.BootstrapLifetime)}
	v.expiry = m.ticketExpiry.PushBack(v)
	v.unused = m.unusedTickets.PushBack(v)
	m.tickets[id] = v
	m.ticketsPerAddress[address]++
	return text, nil
}

func (m *Manager) Create(key, address string, body []byte) (CreateResult, error) {
	if frame.ParseHello(body) != nil {
		return CreateResult{}, ErrProtocol
	}
	id, err := tokenHash(key)
	if err != nil {
		return CreateResult{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	v := m.tickets[id]
	if v == nil || !now.Before(v.deadline) {
		return CreateResult{}, ErrAuthentication
	}
	if m.stopping {
		return CreateResult{}, ErrClosed
	}
	if v.result.Session != nil {
		// v1 HELLO has exactly one valid encoding. Admission has already
		// validated that encoding and the issuance may be replayed safely.
		select {
		case <-v.result.Session.lifetime.Done():
			return CreateResult{}, ErrAuthentication
		default:
		}
		result := v.result
		result.Welcome = frame.Encode(frame.Welcome, 0, nil)
		return result, nil
	}
	owner := v.owner
	limit, local := m.config.Limits, owner.profile.Limits
	globalRate, globalOK := m.newSessions.consume(now, limit.NewSessionsPerMinute, limit.NewSessionsBurst)
	profileRate, profileOK := owner.newSessions.consume(now, local.NewSessionsPerMinute, local.NewSessionsBurst)
	if !globalOK || !profileOK || len(m.sessions) >= limit.MaxSessionsGlobal || owner.sessions >= local.MaxSessions ||
		(limit.MaxSessionsPerIP > 0 && m.sessionsPerAddress[address] >= limit.MaxSessionsPerIP) {
		m.counters.limited.Add(1)
		return CreateResult{}, ErrLimit
	}
	text, sessionID, err := m.tokens.issue(TokenSession)
	if err != nil {
		return CreateResult{}, err
	}
	if m.sessions[sessionID] != nil || m.retired[sessionID] != nil {
		return CreateResult{}, ErrLimit
	}
	limit.MaxStreamsPerSession = local.MaxStreamsPerSession
	limit.MaxPendingPerSession = local.MaxPendingPerSession
	s := newSession(sessionOptions{
		manager: m, quota: owner, profile: owner.profile, limits: limit, timeouts: m.config.Timeouts,
	})
	m.sessions[sessionID] = s
	m.drained.Add(1)
	m.registrations[s] = registration{key: sessionID, ticketKey: id, address: address, profile: owner}
	m.sessionsPerAddress[address]++
	owner.sessions++
	m.newSessions, owner.newSessions = globalRate, profileRate
	m.usedTicket(v)
	v.result = CreateResult{Token: text, Session: s}
	m.counters.created.Add(1)
	return CreateResult{Token: text, Session: s, Welcome: frame.Encode(frame.Welcome, 0, nil)}, nil
}

func (m *Manager) HasBootstrap(value string) bool {
	id, err := tokenHash(value)
	if err != nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	v := m.tickets[id]
	return !m.stopping && v != nil && time.Now().Before(v.deadline)
}

func (m *Manager) Get(value string) (*Session, error) {
	id, err := tokenHash(value)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	s := m.sessions[id]
	stopping := m.stopping
	m.mu.RUnlock()
	if s == nil || stopping {
		return nil, ErrAuthentication
	}
	select {
	case <-s.lifetime.Done():
		return nil, ErrAuthentication
	default:
	}
	return s, nil
}

func (m *Manager) CloseToken(value string) error {
	id, err := tokenHash(value)
	if err != nil {
		return err
	}
	m.mu.RLock()
	s, old := m.sessions[id], m.retired[id]
	finished := old != nil && time.Now().Before(old.Value.(retiredToken).deadline)
	m.mu.RUnlock()
	if s != nil {
		s.Close()
		return nil
	}
	if finished {
		return nil
	}
	return ErrAuthentication
}

func (m *Manager) ReserveWebSocketLane() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping || m.sockets >= m.config.Limits.MaxStreamsGlobal {
		m.counters.limited.Add(1)
		return false
	}
	m.sockets++
	return true
}

func (m *Manager) ReleaseWebSocketLane() {
	m.mu.Lock()
	m.sockets--
	m.mu.Unlock()
}

func (m *Manager) acquireStream(entry *profileQuota) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return false
	}
	limit, local := m.config.Limits, entry.profile.Limits
	if m.streams >= limit.MaxStreamsGlobal || m.dialling >= limit.MaxBackendDialsInFlight ||
		entry.streams >= local.MaxStreams || entry.dialling >= local.MaxBackendDialsInFlight {
		return false
	}
	now := time.Now()
	globalRate, globalOK := m.newStreams.consume(now, limit.NewStreamsPerMinute, limit.NewStreamsBurst)
	profileRate, profileOK := entry.newStreams.consume(now, local.NewStreamsPerMinute, local.NewStreamsBurst)
	if !globalOK || !profileOK {
		return false
	}
	m.newStreams, entry.newStreams = globalRate, profileRate
	m.streams++
	m.dialling++
	entry.streams++
	entry.dialling++
	m.counters.opened.Add(1)
	return true
}

func (m *Manager) backendDialFinished(entry *profileQuota, failed bool) {
	m.mu.Lock()
	m.dialling--
	entry.dialling--
	m.mu.Unlock()
	if failed {
		m.counters.dialFailures.Add(1)
	}
}

func (m *Manager) streamFinished(entry *profileQuota) {
	m.mu.Lock()
	m.streams--
	entry.streams--
	m.mu.Unlock()
}

func (m *Manager) changePendingBudget(bytes, items int, class pendingClass) bool {
	m.budgetMu.Lock()
	defer m.budgetMu.Unlock()
	if bytes > 0 || items > 0 {
		limit := m.pendingLimits[class]
		if bytes > limit.bytes || items > limit.items || m.pendingGlobalCost > int64(limit.bytes-bytes) ||
			m.pendingGlobalItems > int64(limit.items-items) {
			m.counters.limited.Add(1)
			return false
		}
	}
	if int64(bytes) < -m.pendingGlobalCost || int64(items) < -m.pendingGlobalItems {
		panic("unbalanced WEB relay budget release")
	}
	m.pendingGlobalCost += int64(bytes)
	m.pendingGlobalItems += int64(items)
	if (bytes < 0 || items < 0) && m.budgetChanged != nil {
		close(m.budgetChanged)
		m.budgetChanged = nil
	}
	return true
}

// Reserve the destination frame and choose its size in the same critical
// section. A different session cannot exhaust the budget between those steps.
func (m *Manager) reserveDownlinkRead(want int) (int, <-chan struct{}) {
	m.budgetMu.Lock()
	defer m.budgetMu.Unlock()
	limit := m.pendingLimits[pendingDownlink]
	if m.pendingGlobalItems < int64(limit.items) && m.pendingGlobalCost < int64(limit.bytes-dataFrameOverhead) {
		size := min(want, limit.bytes-int(m.pendingGlobalCost)-dataFrameOverhead)
		m.pendingGlobalCost += int64(size + dataFrameOverhead)
		m.pendingGlobalItems++
		return size, nil
	}
	m.counters.limited.Add(1)
	return 0, m.budgetSignalLocked()
}

func withoutReserve(limit, amount, count int) int {
	if count <= 0 || amount > limit/count {
		return 0
	}
	return limit - amount*count
}

func (m *Manager) ChangeBufferBudget(bytes int) bool {
	return m.changePendingBudget(bytes, 0, pendingDownlink)
}

func (m *Manager) budgetSignal() <-chan struct{} {
	m.budgetMu.Lock()
	defer m.budgetMu.Unlock()
	return m.budgetSignalLocked()
}

func (m *Manager) budgetSignalLocked() <-chan struct{} {
	if m.budgetChanged == nil {
		m.budgetChanged = make(chan struct{})
	}
	return m.budgetChanged
}

func (m *Manager) Capacity() Capacity {
	m.mu.RLock()
	result := Capacity{Sessions: len(m.sessions), Streams: m.streams, BackendDialsInFlight: m.dialling}
	m.mu.RUnlock()
	m.budgetMu.Lock()
	result.PendingBytes, result.PendingItems = m.pendingGlobalCost, m.pendingGlobalItems
	m.budgetMu.Unlock()
	return result
}

func (m *Manager) Metrics() Metrics {
	a := &m.counters
	return Metrics{SessionsCreated: a.created.Load(), SessionsClosed: a.closed.Load(), StreamsOpened: a.opened.Load(),
		StreamsRejected: a.rejected.Load(), BackendDialFailures: a.dialFailures.Load(), BytesUp: a.up.Load(),
		BytesDown: a.down.Load(), LimitHits: a.limited.Load()}
}

func (m *Manager) Shutdown() {
	m.shutdown.Do(func() {
		m.mu.Lock()
		m.stopping = true
		close(m.stop)
		live := m.snapshot()
		m.mu.Unlock()
		for _, s := range live {
			s.Close()
		}
		m.drained.Wait()
		<-m.reaped
	})
}

func (m *Manager) snapshot() []*Session {
	live := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		live = append(live, s)
	}
	return live
}

func (m *Manager) sessionFinished(s *Session) {
	m.mu.Lock()
	entry, ok := m.registrations[s]
	if !ok {
		m.mu.Unlock()
		return
	}
	delete(m.registrations, s)
	delete(m.sessions, entry.key)
	if v := m.tickets[entry.ticketKey]; v != nil && v.result.Session == s {
		m.deleteTicket(v)
	}
	decrement(m.sessionsPerAddress, entry.address)
	entry.profile.sessions--
	now := time.Now()
	cap := 16 * min(math.MaxInt/16, m.config.Limits.MaxSessionsGlobal)
	if cap > 0 {
		if len(m.retired) >= cap {
			m.unretire(m.retiredOrder.Front())
		}
		m.retired[entry.key] = m.retiredOrder.PushBack(retiredToken{entry.key, now.Add(m.config.Timeouts.BootstrapLifetime)})
	}
	m.counters.closed.Add(1)
	m.mu.Unlock()
	s.backendWG.Wait()
	m.drained.Done()
}

func decrement(counts map[string]int, address string) {
	if counts[address] <= 1 {
		delete(counts, address)
	} else {
		counts[address]--
	}
}

func (m *Manager) usedTicket(v *ticket) {
	if v.unused != nil {
		m.unusedTickets.Remove(v.unused)
		v.unused = nil
		decrement(m.ticketsPerAddress, v.origin)
	}
}

func (m *Manager) deleteTicket(v *ticket) {
	m.usedTicket(v)
	m.ticketExpiry.Remove(v.expiry)
	delete(m.tickets, v.id)
}

func (m *Manager) unretire(element *list.Element) {
	delete(m.retired, element.Value.(retiredToken).id)
	m.retiredOrder.Remove(element)
}

func (m *Manager) removeExpiredBootstrapsLocked(now time.Time) {
	for item := m.ticketExpiry.Front(); item != nil; item = m.ticketExpiry.Front() {
		v := item.Value.(*ticket)
		if now.Before(v.deadline) {
			break
		}
		m.deleteTicket(v)
	}
	for item := m.retiredOrder.Front(); item != nil; item = m.retiredOrder.Front() {
		if now.Before(item.Value.(retiredToken).deadline) {
			break
		}
		m.unretire(item)
	}
}

func (m *Manager) expire() {
	defer close(m.reaped)
	interval := max(time.Second, min(30*time.Second, m.config.Timeouts.ReconnectGrace/2))
	check := time.NewTicker(interval)
	defer check.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-check.C:
			m.reap(time.Now())
		}
	}
}

func (m *Manager) reap(now time.Time) {
	m.mu.Lock()
	m.removeExpiredBootstrapsLocked(now)
	live := m.snapshot()
	m.mu.Unlock()
	for _, s := range live {
		s.mu.Lock()
		attached := s.activePolls > 0 || s.activeDownlinks > 0 ||
			s.httpUploading || len(s.httpLaneUploads) > 0 || s.websocketActive || len(s.websocketLanes) > 0
		if !attached && now.Sub(s.lastActivity) >= m.config.Timeouts.ReconnectGrace {
			s.closeLocked()
		}
		s.mu.Unlock()
	}
}
