// Command beacon stands in for an implant in the VM tests. "beacon
// HOST:PORT" dials out and holds the connection; "beacon idle" only
// sleeps. It is built for the test, so its hash is in no baseline.
package main

import (
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] != "idle" {
		if c, err := net.DialTimeout("tcp", os.Args[1], time.Minute); err == nil {
			defer c.Close()
		}
	}
	time.Sleep(time.Hour)
}
