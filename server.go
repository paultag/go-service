/* {{{ Copyright (c) Paul R. Tagliamonte <paultag@gmail.org>, 2015
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE. }}} */

package service

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

func readOneByte(c net.Conn) (byte, error) {
	out := make([]byte, 1)
	_, err := c.Read(out)
	return out[0], err
}

func ServeConn(conn net.Conn) {
	conn.Write([]byte{'m'})
	rpc.ServeConn(conn)
}

func Client(conn net.Conn) *rpc.Client {
	conn.Write([]byte{'r'})
	return rpc.NewClient(conn)
}

func Handle(listener *Listener, coordinator Coordinator) {
	coordinator.Register()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error: %s\n", err)
			continue
		}
		class, err := readOneByte(conn)
		if err != nil {
			conn.Close()
		}

		switch class {
		case 'm':
			log.Printf("Minion has connected.\n")
			mConn := conn.(*Conn)
			go coordinator.Handle(rpc.NewClient(conn), mConn)
		case 'r':
			log.Printf("Administrator has connected.\n")
			go rpc.ServeConn(conn)
		default:
			log.Printf("No idea what that was. Closing. Value %c\n", class)
			conn.Close()
		}
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
	Name         string
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

	if len(peerCertificates) <= 0 {
		return nil, fmt.Errorf("No peer certs during handshake")
	}

	for _, cert := range peerCertificates {
		tlsConn.CommonNames = append(tlsConn.CommonNames, cert.Subject.CommonName)
	}
	tlsConn.Name = tlsConn.CommonNames[0]

	return tlsConn, nil
}

func (l *Listener) Addr() net.Addr {
	return l.netListener.Addr()
}

func (l *Listener) Close() error {
	return l.netListener.Close()
}

// vim: foldmethod=marker
