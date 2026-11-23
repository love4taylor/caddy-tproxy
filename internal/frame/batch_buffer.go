package frame

import "math/bits"

const (
	InitialBatchBufferBytes = 4 << 10
	batchBufferClasses      = 10
	maxCachedBatchBytes     = InitialBatchBufferBytes << (batchBufferClasses - 1)
	smallHeaderRoom         = 512
)

// BatchBuffer owns storage for one contiguous carrier body.
type BatchBuffer struct {
	Bytes []byte
	cache chan []byte
}

type batchBufferClass struct {
	aligned, smallHeaders, headers chan []byte
}

// Bound idle storage across both directions and all relay instances. Large
// classes keep one idle buffer each. Owners still charge live capacity.
var batchBufferCache = func() [batchBufferClasses]batchBufferClass {
	var cache [batchBufferClasses]batchBufferClass
	for i := range cache {
		size := InitialBatchBufferBytes << i
		cache[i].aligned = make(chan []byte, min(8, max(1, (256<<10)/size)))
		if size >= DataChunk && size < maxCachedBatchBytes {
			cache[i].smallHeaders = make(chan []byte, 1)
			cache[i].headers = make(chan []byte, 1)
		}
	}
	return cache
}()

func batchStorage(size, limit int) (int, chan []byte) {
	class := bits.Len(uint(size-1)) - bits.Len(InitialBatchBufferBytes-1)
	block := InitialBatchBufferBytes << class
	if block <= limit && block-size <= min(InitialBatchBufferBytes, block/8) {
		return block, batchBufferCache[class].aligned
	}
	previous := block / 2
	if previous >= DataChunk {
		if capacity := previous + smallHeaderRoom; size <= capacity && capacity <= limit {
			return capacity, batchBufferCache[class-1].smallHeaders
		}
		if capacity := previous + InitialBatchBufferBytes; size <= capacity && capacity <= limit {
			return capacity, batchBufferCache[class-1].headers
		}
	}
	return size, nil
}

// BorrowBatchBuffer reserves backing capacity before acquiring storage. The
// caller owns the charge and recycles the buffer after its last use.
func BorrowBatchBuffer(size, limit int, reserve func(int) bool) BatchBuffer {
	if size <= 0 || size > limit {
		return BatchBuffer{}
	}
	capacity := size
	var cache chan []byte
	if size >= InitialBatchBufferBytes && size <= maxCachedBatchBytes {
		capacity, cache = batchStorage(size, limit)
	}
	if !reserve(capacity) {
		if capacity == size || !reserve(size) {
			return BatchBuffer{}
		}
		capacity, cache = size, nil
	}
	if cache != nil {
		select {
		case storage := <-cache:
			return BatchBuffer{Bytes: storage[:size], cache: cache}
		default:
		}
	}
	return BatchBuffer{Bytes: make([]byte, size, capacity), cache: cache}
}

// Recycle relinquishes storage. The caller must finish using Bytes first.
func (b *BatchBuffer) Recycle() {
	if b.cache != nil {
		select {
		case b.cache <- b.Bytes[:cap(b.Bytes)]:
		default:
		}
	}
	*b = BatchBuffer{}
}
