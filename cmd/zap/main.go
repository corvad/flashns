package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"runtime"

	"github.com/corvad/dns/dns"
)

type staticProvider []dns.Record

func (p staticProvider) Records() ([]dns.Record, error) {
	return p, nil
}

func main() {
	go http.ListenAndServe("localhost:6060", nil)
	const name = "\x07example\x03com\x00"
	p := staticProvider{
		{Name: name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 60, Data: []byte{1, 2, 3, 4}},
		{Name: name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 60, Data: []byte{5, 6, 7, 8}},
		{Name: name, Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 60, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
	}
	srv, err := dns.NewUDPServer("localhost:53535", p)
	if err != nil {
		log.Fatal(err)
	}
	srv.Start(runtime.GOMAXPROCS(0))
	log.Println("DNS server started on localhost:53535")
	select {}
}
