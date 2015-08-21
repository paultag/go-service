package service

import (
	"crypto/tls"
	"log"
	"net/rpc"
)

func ClientFromKeys(network, laddr, clientCrt, clientKey, caCrt string) (*rpc.Client, error) {
	cert, err := tls.LoadX509KeyPair(clientCrt, clientKey)
	if err != nil {
		log.Fatalf("client: loadkeys: %s", err)
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

	conn, err := tls.Dial(network, laddr, &config)
	if err != nil {
		return nil, err
	}
	client := rpc.NewClient(conn)
	return client, nil
}
