package service

import (
	"crypto/tls"
	"net"
)

func DialFromKeys(laddr, clientCrt, clientKey, caCrt string) (net.Conn, error) {
	cert, err := tls.LoadX509KeyPair(clientCrt, clientKey)
	if err != nil {
		return nil, err
	}
	/* XXX: Do Validation of the client cert, and ensure the extended client
	 *      usage bit is flipped, otherwise the server will choke on it */

	caPool, err := caFileToPool(caCrt)
	if err != nil {
		return nil, err
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		RootCAs:      caPool,
	}

	conn, err := tls.Dial("tcp", laddr, &config)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
