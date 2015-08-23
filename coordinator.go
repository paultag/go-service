package service

import (
	"net/rpc"
)

type Coordinator interface {
	Handle(*rpc.Client, *Conn)
}
