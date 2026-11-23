package session

// Retiring a lane can discard its cached responses, but it must never make
// the stream ID reusable. The wire's 24-bit space needs at most 2 MiB of
// bitmap data. Keep the first page inline for ordinary sessions and charge
// additional pages to the session budget before allocating them.
type streamIDs struct {
	first      [64]uint64
	firstIndex uint16
	hasFirst   bool
	extra      map[uint16]*[64]uint64
}

// Include the allocation and its entry in the sparse page map.
const streamIDPageCost = 576

func (ids *streamIDs) page(index uint16) *[64]uint64 {
	if ids.hasFirst && ids.firstIndex == index {
		return &ids.first
	}
	return ids.extra[index]
}

func (ids *streamIDs) contains(id uint32) bool {
	page := ids.page(uint16(id >> 12))
	return page != nil && page[(id>>6)&63]&(uint64(1)<<(id&63)) != 0
}

func (ids *streamIDs) add(id uint32) bool {
	index := uint16(id >> 12)
	page := ids.page(index)
	allocated := false
	if !ids.hasFirst {
		ids.firstIndex = index
		ids.hasFirst = true
		page = &ids.first
	} else if page == nil {
		if ids.extra == nil {
			ids.extra = make(map[uint16]*[64]uint64)
		}
		page = new([64]uint64)
		ids.extra[index] = page
		allocated = true
	}
	page[(id>>6)&63] |= uint64(1) << (id & 63)
	return allocated
}
