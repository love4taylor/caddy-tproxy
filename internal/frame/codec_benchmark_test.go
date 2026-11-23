package frame

import (
	"strconv"
	"testing"
)

func BenchmarkFrameDecoding(b *testing.B) {
	for _, count := range []int{1, 4, 32, 512, 4096} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			var wire []byte
			for range count {
				wire = append(wire, Encode(Data, 1, make([]byte, 16))...)
			}
			b.SetBytes(int64(len(wire)))
			b.ReportAllocs()
			for b.Loop() {
				parts, err := ParseAll(wire, MaxPayload)
				if err != nil || len(parts) != count {
					b.Fatal(err)
				}
			}
		})
	}
}
