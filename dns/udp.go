package dns

import (
	"net"
	"sync"
)

type UDPServer struct {
	cache *Cache
	conn  *net.UDPConn
	wg    sync.WaitGroup
}

func NewUDPServer(addr string, p Provider) (*UDPServer, error) {
	cache, err := NewCache(p)
	if err != nil {
		return nil, err
	}

	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, err
	}

	return &UDPServer{
		cache: cache,
		conn:  conn,
	}, nil
}

func (s *UDPServer) Start(nproc int) {
	for i := 0; i < nproc; i++ {
		s.wg.Add(1)
		go s.serve()
	}
}

func (s *UDPServer) Close() error {
	err := s.conn.Close()
	s.wg.Wait()
	return err
}

func (s *UDPServer) serve() {
	defer s.wg.Done()
	buf := make([]byte, 512)
	for {
		n, src, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}

		r := handle(buf, n, s.cache)
		if r > 0 {
			s.conn.WriteToUDPAddrPort(buf[:r], src)
		}
	}
}
