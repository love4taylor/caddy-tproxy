package session

import (
	"errors"
	"fmt"
	"math"

	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/frame"
)

const dataFrameOverhead = queueItemCost + frame.HeaderSize

type pendingCapacity struct{ bytes, items int }

type pendingLimits [pendingControl + 1]pendingCapacity

func ValidateBudget(cfg config.Config) error {
	l := cfg.Limits
	if l.MaxSessionsGlobal < 1 {
		return errors.New("max_sessions_global must be positive")
	}
	reservedBytes, reservedItems := pendingControlReserve(l)
	if reservedBytes > l.MaxPendingGlobal/l.MaxSessionsGlobal ||
		reservedItems > l.MaxPendingItemsGlobal/l.MaxSessionsGlobal {
		return errors.New("global pending limits cannot hold the per-session control reserves")
	}
	if withoutReserve(l.MaxPendingGlobal, reservedBytes, l.MaxSessionsGlobal) <= dataFrameOverhead ||
		withoutReserve(l.MaxPendingItemsGlobal, reservedItems, l.MaxSessionsGlobal) == 0 {
		return errors.New("global pending limits leave no room for DATA after the control reserves")
	}
	for _, profile := range cfg.Profiles {
		effective := l
		local := profile.Limits.WithDefaults(l)
		effective.MaxPendingPerSession = local.MaxPendingPerSession
		effective.MaxStreamsPerSession = local.MaxStreamsPerSession
		capacity := pendingLimit(effective, pendingDownlink)
		if capacity.bytes <= dataFrameOverhead {
			return fmt.Errorf("profile %q: max_pending_per_session leaves no room for downlink DATA after the control and uplink reserves", profile.Name)
		}
		if capacity.items == 0 {
			return fmt.Errorf("profile %q: max_pending_items_per_session leaves no room for downlink DATA after the control and uplink reserves", profile.Name)
		}
	}
	return nil
}

func pendingControlReserve(l config.Limits) (int, int) {
	const bytesPerControl = queueItemCost + frame.HeaderSize + 4
	const maxStreams = (math.MaxInt/bytesPerControl - controlReserveExtraItems) / controlReserveItemsPerStream
	if l.MaxStreamsPerSession > maxStreams {
		return l.MaxPendingPerSession, l.MaxPendingItemsPerSession
	}
	entries := controlReserveExtraItems + controlReserveItemsPerStream*l.MaxStreamsPerSession
	return bytesPerControl * entries, entries
}

func pendingLimit(l config.Limits, kind pendingClass) (limit pendingCapacity) {
	limit = pendingCapacity{l.MaxPendingPerSession, l.MaxPendingItemsPerSession}
	if kind == pendingControl {
		return
	}
	controls, controlEntries := pendingControlReserve(l)
	limit.bytes, limit.items = max(0, limit.bytes-controls), max(0, limit.items-controlEntries)
	if kind == pendingDownlink {
		uploadEntries := min(frame.MaxBatchFrames, l.MaxBodyBytes/frame.HeaderSize)
		limit.items = max(0, limit.items-uploadEntries)
		limit.bytes = max(0, limit.bytes-l.MaxBodyBytes)
		limit.bytes = max(0, limit.bytes-queueItemCost*uploadEntries)
	}
	return
}

// Limits depend only on configuration. Compute them before either budget lock
// is used in the data path.
func sessionPendingLimits(l config.Limits) pendingLimits {
	return pendingLimits{
		pendingUplink:   pendingLimit(l, pendingUplink),
		pendingDownlink: pendingLimit(l, pendingDownlink),
		pendingControl:  pendingLimit(l, pendingControl),
	}
}

func globalPendingLimits(l config.Limits) pendingLimits {
	perSessionBytes, perSessionItems := pendingControlReserve(l)
	data := pendingCapacity{
		bytes: withoutReserve(l.MaxPendingGlobal, perSessionBytes, l.MaxSessionsGlobal),
		items: withoutReserve(l.MaxPendingItemsGlobal, perSessionItems, l.MaxSessionsGlobal),
	}
	return pendingLimits{
		pendingUplink:   data,
		pendingDownlink: data,
		pendingControl:  {l.MaxPendingGlobal, l.MaxPendingItemsGlobal},
	}
}

func (s *Session) dataFrameAllowanceLocked(want int) int {
	limit := s.pendingLimits[pendingDownlink]
	if s.pendingItems >= limit.items || s.pendingCost >= limit.bytes {
		return 0
	}
	return min(want, max(0, limit.bytes-s.pendingCost-dataFrameOverhead))
}

func (s *Session) reservePendingLocked(bytes, items int, kind pendingClass) bool {
	limit := s.pendingLimits[kind]
	if bytes <= 0 || items < 0 || bytes > limit.bytes-s.pendingCost || items > limit.items-s.pendingItems {
		return false
	}
	if s.manager != nil && !s.manager.changePendingBudget(bytes, items, kind) {
		return false
	}
	s.pendingCost, s.pendingItems = s.pendingCost+bytes, s.pendingItems+items
	return true
}

func (s *Session) releasePendingLocked(bytes, items int) {
	if bytes == 0 && items == 0 {
		return
	}
	if bytes < 0 || items < 0 || bytes > s.pendingCost || items > s.pendingItems {
		panic("invalid session pending budget release")
	}
	s.pendingCost, s.pendingItems = s.pendingCost-bytes, s.pendingItems-items
	if s.manager != nil {
		s.manager.changePendingBudget(-bytes, -items, pendingUplink)
	}
	if changed := s.budgetNotify; changed != nil {
		s.budgetNotify = nil
		close(changed)
	}
}

func (s *Session) accountBuffer(bytes int) bool {
	return s.manager == nil || s.manager.ChangeBufferBudget(bytes)
}

func (s *Session) budgetSignalLocked() <-chan struct{} {
	if changed := s.budgetNotify; changed != nil {
		return changed
	}
	changed := make(chan struct{})
	s.budgetNotify = changed
	return changed
}
