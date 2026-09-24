package dns

import "strconv"

type Type uint16

const (
	TypeA      Type = 1
	TypeNS     Type = 2
	TypeCNAME  Type = 5
	TypeSOA    Type = 6
	TypePTR    Type = 12
	TypeMX     Type = 15
	TypeTXT    Type = 16
	TypeAAAA   Type = 28
	TypeLOC    Type = 29
	TypeSRV    Type = 33
	TypeNAPTR  Type = 35
	TypeKX     Type = 36
	TypeDNAME  Type = 39
	TypeOPT    Type = 41
	TypeDS     Type = 43
	TypeRRSIG  Type = 46
	TypeNSEC   Type = 47
	TypeDNSKEY Type = 48
	TypeSPF    Type = 99
	TypeIXFR   Type = 251
	TypeAXFR   Type = 252
	TypeALL    Type = 255
)

var typeName = map[Type]string{
	TypeA:      "A",
	TypeNS:     "NS",
	TypeCNAME:  "CNAME",
	TypeSOA:    "SOA",
	TypePTR:    "PTR",
	TypeMX:     "MX",
	TypeTXT:    "TXT",
	TypeAAAA:   "AAAA",
	TypeLOC:    "LOC",
	TypeSRV:    "SRV",
	TypeNAPTR:  "NAPTR",
	TypeKX:     "KX",
	TypeDNAME:  "DNAME",
	TypeOPT:    "OPT",
	TypeDS:     "DS",
	TypeRRSIG:  "RRSIG",
	TypeNSEC:   "NSEC",
	TypeDNSKEY: "DNSKEY",
	TypeSPF:    "SPF",
	TypeIXFR:   "IXFR",
	TypeAXFR:   "AXFR",
	TypeALL:    "ALL",
}

func (t Type) String() string {
	if s, ok := typeName[t]; ok {
		return s
	}
	return "Type" + strconv.Itoa(int(t))
}

type Class uint16

const (
	ClassIN  Class = 1
	ClassCH  Class = 3
	ClassHS  Class = 4
	ClassANY Class = 255
)

var className = map[Class]string{
	ClassIN:  "IN",
	ClassCH:  "CH",
	ClassHS:  "HS",
	ClassANY: "ANY",
}

func (c Class) String() string {
	if s, ok := className[c]; ok {
		return s
	}
	return "Class" + strconv.Itoa(int(c))
}

type TTL uint32

type Record struct {
	Name  string
	Type  Type
	Class Class
	TTL   TTL
	Data  []byte
}

type Query struct {
	Name  string
	Type  Type
	Class Class
}

type OpCode uint8

const (
	OpCodeQuery  OpCode = 0
	OpCodeIQuery OpCode = 1
	OpCodeStatus OpCode = 2
	OpCodeNotify OpCode = 4
	OpCodeUpdate OpCode = 5
	OpCodeDSO    OpCode = 6
)

type RCODE uint16

const (
	RCODENoError   RCODE = 0
	RCODEFormErr   RCODE = 1
	RCODEServFail  RCODE = 2
	RCODENXDomain  RCODE = 3
	RCODENotImp    RCODE = 4
	RCODEServRef   RCODE = 5
	RCODEYXDomain  RCODE = 6
	RCODEYXRRSet   RCODE = 7
	RCODENXRRSet   RCODE = 8
	RCODENotAuth   RCODE = 9
	RCODENotZone   RCODE = 10
	RCODEDSOTYPENI RCODE = 11
	RCODEBADVERS   RCODE = 16
	RCODEBADSIG    RCODE = 16
	RCODEBADKEY    RCODE = 17
	RCODEBADTIME   RCODE = 18
	RCODEBADMODE   RCODE = 19
	RCODEBADNAME   RCODE = 20
	RCODEBADALG    RCODE = 21
	RCODEBADTRUNC  RCODE = 22
	RCODEBADCOOKIE RCODE = 23
)

type Flags uint16

const (
	FlagQR     Flags = 1 << 15
	FlagOPCODE Flags = 0b0111100000000000
	FlagAA     Flags = 1 << 10
	FlagTC     Flags = 1 << 9
	FlagRD     Flags = 1 << 8
	FlagRA     Flags = 1 << 7
	FlagZ      Flags = 1 << 6
	FlagAD     Flags = 1 << 5
	FlagCD     Flags = 1 << 4
	FlagRCODE  Flags = 0x000F
)
