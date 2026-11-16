// Command beacon stands in for an implant in the VM tests. "beacon
// HOST:PORT" dials out and holds the connection; "beacon listen :PORT
// [HOST:PORT]" listens (and also dials, when given a target); "beacon idle"
// only sleeps. It is built
// for the test, so its hash is in no baseline.
package main

import (
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) > 2 && os.Args[1] == "listen" {
		if l, err := net.Listen("tcp", os.Args[2]); err == nil {
			go func() {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					defer c.Close()
				}
			}()
		}
		if len(os.Args) > 3 {
			if c, err := net.DialTimeout("tcp", os.Args[3], time.Minute); err == nil {
				defer c.Close()
			}
		}
	} else if len(os.Args) > 1 && os.Args[1] != "idle" {
		if c, err := net.DialTimeout("tcp", os.Args[1], time.Minute); err == nil {
			defer c.Close()
		}
	}
	time.Sleep(time.Hour)
}
