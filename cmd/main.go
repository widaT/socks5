package main

import (
	"context"
	"fmt"
	"github.com/widaT/socks5"
	"net"
)

func main() {
	l, err := net.Listen("tcp", ":9999")
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err)
			return
		}
		go func() {

			err := socks5.HandleSock5(context.Background(), conn)
			if err != nil {
				fmt.Printf("%+v\n", err)
			}
		}()
	}
}
