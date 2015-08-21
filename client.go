package service

import (
	"crypto/tls"
	"log"
	"net/rpc"
)

func ClientFromKeys(network, laddr, clientCrt, clientKey, caCrt string) (*rpc.Client, error) {
	cert, err := tls.LoadX509KeyPair("certs/personal.crt", "certs/personal.key")
	if err != nil {
		log.Fatalf("client: loadkeys: %s", err)
	}

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
