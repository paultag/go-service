package service

import (
	"net"
	"net/rpc"
)

type Coordinator interface {
	Handle(*rpc.Client, net.Conn)
}
