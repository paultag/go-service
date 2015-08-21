package service

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

func caFileToPool(path string) (*x509.CertPool, error) {
	caPool := x509.NewCertPool()
	x509CaCrt, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if ok := caPool.AppendCertsFromPEM(x509CaCrt); !ok {
		return nil, fmt.Errorf("Error appending CA cert from PEM!")
	}
	return caPool, nil
}
