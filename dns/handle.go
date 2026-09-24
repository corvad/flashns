package dns

import "encoding/binary"

func handle(buf []byte, n int, cache *Cache) int {
	var key [259]byte

	k := 0
	i := 12
	for i < n {
		c := buf[i]
		key[k] = lowercaseLUT[c]
		i++
		k++
		if c == 0 {
			break
		}
		if k == 255 {
			break
		}
	}
	if i+4 > n {
		return 0
	}

	copy(key[k:], buf[i:i+4])
	end := i + 4

	result, ok := cache.Lookup(key[:k], binary.LittleEndian.Uint32(buf[i:end]))
	if !ok {
		return 0
	}
	size := end + len(result) - 10
	if size > 512 {
		return 0
	}

	buf[2] = result[0] | buf[2]&byte(FlagRD>>8)
	buf[3] = result[1]
	copy(buf[4:12], result[2:10])
	copy(buf[end:], result[10:])
	return size
}
