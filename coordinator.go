package service

import (
	"net/rpc"
)

type Coordinator interface {
	Register()
	Handle(*rpc.Client, *Conn)
}
