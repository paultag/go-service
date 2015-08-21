package service

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/rpc"
)

func ClientFromKeys(network, laddr, clientCrt, clientKey, caCrt string) (*rpc.Client, error) {
	cert, err := tls.LoadX509KeyPair("certs/personal.crt", "certs/personal.key")
	if err != nil {
		log.Fatalf("client: loadkeys: %s", err)
	}

	caPool := x509.NewCertPool()
	x509CaCrt, err := ioutil.ReadFile(caCrt)
	if err != nil {
		return nil, err
	}
	if ok := caPool.AppendCertsFromPEM(x509CaCrt); !ok {
		return nil, fmt.Errorf("Error appending CA cert from PEM!")
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
