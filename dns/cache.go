package dns

import (
	"encoding/binary"
	"sync/atomic"
)

type Cache struct {
	ptr atomic.Pointer[map[string]map[uint32][]byte]
}

func (c *Cache) Lookup(name []byte, key uint32) ([]byte, bool) {
	l := c.ptr.Load()
	if l == nil {
		return nil, false
	}
	pkt, ok := (*l)[string(name)][key]
	return pkt, ok
}

func (c *Cache) Reload(p Provider) error {
	l, err := Compile(p)
	if err != nil {
		return err
	}
	c.ptr.Store(&l)
	return nil
}

func NewCache(p Provider) (*Cache, error) {
	c := &Cache{}
	err := c.Reload(p)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func Compile(p Provider) (map[string]map[uint32][]byte, error) {
	records, err := p.Records()
	if err != nil {
		return nil, err
	}

	groups := make(map[Query][]Record)
	for _, r := range records {
		n := []byte(r.Name)
		for i := range n {
			n[i] = lowercaseLUT[n[i]]
		}
		q := Query{Name: string(n), Type: r.Type, Class: r.Class}
		groups[q] = append(groups[q], r)
	}

	c := make(map[string]map[uint32][]byte)

	for q, set := range groups {
		pkt := encodePacket(FlagQR|FlagAA, set, nil, nil)
		fqdn := fqdnKey(q)
		m := c[fqdn]
		if m == nil {
			m = make(map[uint32][]byte)
			c[fqdn] = m
		}
		m[typeClassKey(q)] = pkt
	}

	return c, nil
}

func fqdnKey(q Query) string {
	return q.Name
}

func typeClassKey(q Query) uint32 {
	return uint32(q.Class>>8|q.Class<<8)<<16 | uint32(q.Type>>8|q.Type<<8)
}

func encodePacket(flags Flags, answer, authority, additional []Record) []byte {
	buf := make([]byte, 0, 128)
	buf = binary.BigEndian.AppendUint16(buf, uint16(flags))
	buf = binary.BigEndian.AppendUint16(buf, 1)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(answer)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(authority)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(additional)))
	for _, r := range answer {
		buf = appendRecord(buf, r)
	}
	for _, r := range authority {
		buf = appendRecord(buf, r)
	}
	for _, r := range additional {
		buf = appendRecord(buf, r)
	}
	return buf
}

func appendRecord(buf []byte, r Record) []byte {
	buf = append(buf, 0xC0, 0x0C)
	buf = binary.BigEndian.AppendUint16(buf, uint16(r.Type))
	buf = binary.BigEndian.AppendUint16(buf, uint16(r.Class))
	buf = binary.BigEndian.AppendUint32(buf, uint32(r.TTL))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(r.Data)))
	buf = append(buf, r.Data...)
	return buf
}
