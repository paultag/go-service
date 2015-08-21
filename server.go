package service

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/rpc"
)

func ListenFromKeys(laddr, serverCrt, serverKey, caCrt string) (*Listener, error) {
	cert, err := tls.LoadX509KeyPair(serverCrt, serverKey)
	if err != nil {
		return nil, err
	}

	caPool, err := caFileToPool(caCrt)
	if err != nil {
		return nil, err
	}

	l, e := Listen(laddr, caPool, cert)
	if e != nil {
		return nil, e
	}
	return l, nil
}

func Serve(listener *Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error: %s\n", err)
			continue
		}
		go rpc.ServeConn(conn)
	}
}

func Handle(listener *Listener, coordinator Coordinator) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error: %s\n", err)
			continue
		}
		go coordinator.Handle(rpc.NewClient(conn), conn)
	}
}

func Listen(laddr string, caPool *x509.CertPool, serverCertPair tls.Certificate) (*Listener, error) {
	l, e := tls.Listen("tcp", laddr, &tls.Config{
		Certificates: []tls.Certificate{serverCertPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	})
	if e != nil {
		return nil, e
	}
	return &Listener{netListener: l}, nil
}

type Listener struct {
	netListener net.Listener
}

type Conn struct {
	tls.Conn

	Certificates []*x509.Certificate
	CommonNames  []string
}

func (l *Listener) Accept() (net.Conn, error) {
	/* During Accept, we'll do the handshake right off, and ensure that
	 * we have some peer certs (already checked for validity, though) and
	 * pass on information (email, fingerprint) to the code under */

	conn, err := l.netListener.Accept()
	if err != nil {
		return nil, err
	}
	tlsConn := &Conn{
		Conn:         *conn.(*tls.Conn),
		Certificates: []*x509.Certificate{},
		CommonNames:  []string{},
	}
	tlsConn.Handshake()
	peerCertificates := tlsConn.ConnectionState().PeerCertificates
	tlsConn.Certificates = peerCertificates

	for _, cert := range peerCertificates {
		tlsConn.CommonNames = append(tlsConn.CommonNames, cert.Subject.CommonName)
	}

	return tlsConn, nil
}

func (l *Listener) Addr() net.Addr {
	return l.netListener.Addr()
}

func (l *Listener) Close() error {
	return l.netListener.Close()
}
