package dns

import (
	"encoding/binary"
	"strings"
	"sync/atomic"
)

type Cache map[string]*atomic.Pointer[map[uint32][]byte]

func Compile(p Provider) (Cache, error) {
	records, err := p.Records()
	if err != nil {
		return nil, err
	}

	groups := make(map[Query][]Record)
	for _, r := range records {
		name := strings.ToLower(r.Name)
		q := Query{Name: name, Type: r.Type, Class: r.Class}
		groups[q] = append(groups[q], r)
	}

	c := make(Cache)

	for q, set := range groups {
		pkt := encodePacket(FlagQR|FlagAA, set, nil, nil)
		fqdn := fqdnKey(q)
		if c[fqdn] == nil {
			a := &atomic.Pointer[map[uint32][]byte]{}
			m := make(map[uint32][]byte)
			a.Store(&m)
			c[fqdn] = a
		}
		(*c[fqdn].Load())[typeClassKey(q)] = pkt
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
		appendRecord(buf, r)
	}
	for _, r := range authority {
		appendRecord(buf, r)
	}
	for _, r := range additional {
		appendRecord(buf, r)
	}
	return buf
}

func appendRecord(buf []byte, r Record) {
	buf = append(buf, 0xC0, 0x0C)
	buf = binary.BigEndian.AppendUint16(buf, uint16(r.Type))
	buf = binary.BigEndian.AppendUint16(buf, uint16(r.Class))
	buf = binary.BigEndian.AppendUint32(buf, uint32(r.TTL))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(r.Data)))
	buf = append(buf, r.Data...)
}
