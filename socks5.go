package socks5

import (
	"bufio"
	"context"
	"fmt"
	"github.com/pingcap/errors"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
)

//https://jiajunhuang.com/articles/2019_06_06-socks5.md.html

const (
	VERSION5   = uint8(5)
	NOAUTH     = uint8(0)
	CONNECTCMD = uint8(1)
	/*	BindCommand      = uint8(2)        //暂时不处理
		ASSOCIATECOMMAND = uint8(3)*/
	IPV4ADDR = uint8(1) //ipv4地址
	DNADDR   = uint8(3) //域名地址
	IPV6ADDR = uint8(4) //地址

	SUCCEEDED                     = uint8(0)
	GENERALSOCKSSERVERFAILURE     = uint8(1)
	CONNECTIONNOTALLOWEDBYRULESET = uint8(2)
	NETWORKUNREACHABLE            = uint8(3)
	HOSTUNREACHABLE               = uint8(4)
	CONNECTIONREFUSED             = uint8(5)
	TTLEXPIRED                    = uint8(6)
	COMMANDNOTSUPPORTED           = uint8(7)
	ADDRESSTYPENOTSUPPORTED       = uint8(8)
)

var bufpoll sync.Pool

func init() {
	bufpoll.New = func() interface{} {
		return make([]byte, 32768)
	}
}

type Addr struct {
	Dn   string
	IP   net.IP
	Port int
}

func (a Addr) Addr() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.Dn, strconv.Itoa(a.Port))
}

type Command struct {
	Version      uint8
	Command      uint8
	RemoteAddr   *Addr
	DestAddr     *Addr
	RealDestAddr *Addr
	bufConn      io.Reader
}

func newCommand(bufConn io.Reader) (*Command, error) {
	/**
	+----+-----+-------+------+----------+----------+
	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
	*/
	header := []byte{0, 0, 0}
	if _, err := io.ReadFull(bufConn, header); err != nil {
		return nil, errors.WithStack(err)
	}

	if header[0] != VERSION5 {
		return nil, errors.New(fmt.Sprintf("Unsupported command version: %v", header[0]))
	}

	//dst address
	dest, err := readAddr(bufConn)
	if err != nil {
		return nil, err
	}

	cmd := &Command{
		Version:  VERSION5,
		Command:  header[1],
		DestAddr: dest,
		bufConn:  bufConn,
	}

	return cmd, nil
}

func HandleSock5(ctx context.Context, conn io.ReadWriteCloser) error {
	for {
		buf := bufio.NewReader(conn)
		/**
		+----+----------+----------+
		|VER | NMETHODS | METHODS  |
		+----+----------+----------+
		| 1  |    1     | 1 to 255 |
		+----+----------+----------+
		*/

		version := []byte{0}
		if _, err := buf.Read(version); err != nil {
			return errors.WithStack(err)
		}

		if version[0] != VERSION5 {
			return fmt.Errorf("SOCKS version not match")
		}

		methodCount := []byte{0}
		if _, err := buf.Read(methodCount); err != nil {
			return fmt.Errorf("read methodCount err")
		}

		numMethods := int(methodCount[0])
		methods := make([]byte, numMethods)
		_, err := io.ReadFull(buf, methods)
		if err != nil {
			return errors.WithStack(err)
		}

		/**
		+----+--------+
		|VER | METHOD |
		+----+--------+
		| 1  |   1    |
		+----+--------+
		*/

		//force use noauth
		_, err = conn.Write([]byte{VERSION5, NOAUTH})
		if err != nil {
			return errors.WithStack(err)
		}
		cmd, err := newCommand(buf)
		if err != nil {
			return errors.WithStack(err)
		}

		if err := handleCmd(ctx, cmd, conn); err != nil {
			return errors.WithStack(err)
		}
	}
}

func handleCmd(ctx context.Context, cmd *Command, conn io.ReadWriteCloser) error {
	dest := cmd.DestAddr
	if dest.Dn != "" {
		addr, err := net.ResolveIPAddr("ip", dest.Dn)
		if err != nil {
			if err := replyMsg(conn, HOSTUNREACHABLE, nil); err != nil {
				return errors.WithStack(err)
			}
			return errors.WithStack(err)
		}
		dest.IP = addr.IP
	}

	cmd.RealDestAddr = cmd.DestAddr
	switch cmd.Command {
	case CONNECTCMD:
		return handleConn(conn, cmd)
	default:
		if err := replyMsg(conn, COMMANDNOTSUPPORTED, nil); err != nil {
			return errors.WithStack(err)
		}
		return errors.New("Unsupported command")
	}
}

func handleConn(conn io.ReadWriteCloser, req *Command) error {
	target, err := net.Dial("tcp", req.RealDestAddr.Addr())
	if err != nil {
		msg := err.Error()
		resp := HOSTUNREACHABLE
		if strings.Contains(msg, "refused") {
			resp = CONNECTIONREFUSED
		} else if strings.Contains(msg, "network is unreachable") {
			resp = NETWORKUNREACHABLE
		}
		if err := replyMsg(conn, resp, nil); err != nil {
			return errors.WithStack(err)
		}
		return errors.New(fmt.Sprintf("Connect to %v failed: %v", req.DestAddr, err))
	}
	defer target.Close()

	local := target.LocalAddr().(*net.TCPAddr)
	bind := Addr{IP: local.IP, Port: local.Port}
	if err := replyMsg(conn, SUCCEEDED, &bind); err != nil {
		return errors.WithStack(err)
	}

	errCh := make(chan error, 2)
	go Copy(target, req.bufConn, errCh)
	go Copy(conn, target, errCh)

	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			return e
		}
	}
	return nil
}

func readAddr(r io.Reader) (*Addr, error) {
	d := &Addr{}
	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	switch addrType[0] {
	case IPV4ADDR:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case IPV6ADDR:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case DNADDR:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		DN := make([]byte, addrLen)
		if _, err := io.ReadFull(r, DN); err != nil {
			return nil, err
		}
		d.Dn = string(DN)

	default:
		return nil, errors.New("unkown addr type")
	}

	// get port
	port := []byte{0, 0}
	if _, err := io.ReadFull(r, port); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])
	return d, nil
}

func replyMsg(w io.Writer, resp uint8, addr *Addr) error {
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = IPV4ADDR
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.Dn != "":
		addrType = DNADDR
		addrBody = append([]byte{byte(len(addr.Dn))}, addr.Dn...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = IPV4ADDR
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = IPV6ADDR
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return errors.New("format address error")
	}

	/**
	+----+-----+-------+------+----------+----------+
	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
	*/

	bodyLen := len(addrBody)
	msg := make([]byte, 6+bodyLen)
	msg[0] = VERSION5
	msg[1] = resp
	msg[2] = 0 // RSV
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+bodyLen] = byte(addrPort >> 8)
	msg[4+bodyLen+1] = byte(addrPort & 0xff)
	_, err := w.Write(msg)
	return err
}

func Copy(dst io.ReadWriteCloser, src io.Reader, errCh chan error) {
	b := bufpoll.Get().([]byte)
	_, err := io.CopyBuffer(dst, src, b)
	dst.Close()
	bufpoll.Put(b)
	errCh <- err
}

func HandelSock5Client(ctx context.Context, conn io.ReadWriteCloser, addr string, port int) (*Addr, error) {
	/**
	+----+----------+----------+
	|VER | NMETHODS | METHODS  |
	+----+----------+----------+
	| 1  |    1     | 1 to 255 |
	+----+----------+----------+
	*/

	msg := make([]byte, 3)
	msg[0] = VERSION5
	msg[1] = uint8(1)
	msg[2] = NOAUTH

	_, err := conn.Write(msg)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	log.Printf("send msg %s", string(msg))
	/**
	+----+--------+
	|VER | METHOD |
	+----+--------+
	| 1  |   1    |
	+----+--------+
	*/

	version := []byte{0}
	if _, err := conn.Read(version); err != nil {
		return nil, errors.WithStack(err)
	}

	if version[0] != VERSION5 {
		return nil, fmt.Errorf("SOCKS version not match")
	}

	method := []byte{0}
	if _, err := conn.Read(method); err != nil {
		return nil, fmt.Errorf("read methodCount err")
	}

	if err := queryMsg(conn, CONNECTCMD, addr, port); err != nil {
		return nil, errors.WithStack(err)
	}

	/**
	+----+-----+-------+------+----------+----------+
	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
	*/
	header := []byte{0, 0, 0}
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, errors.WithStack(err)
	}
	if header[0] != VERSION5 {
		return nil, errors.New(fmt.Sprintf("Unsupported command version: %v", header[0]))
	}

	if header[1] != SUCCEEDED {
		return nil, errors.New(fmt.Sprintf("socks5 query err REP  error number: %v", header[1]))
	}

	//bnd address
	bnd, err := readAddr(conn)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return bnd, nil
}

func queryMsg(w io.Writer, cmd uint8, raddr string, port int) error {
	addr := Addr{Port: port}
	ip := net.ParseIP(raddr)
	if ip != nil {
		addr.IP = ip
	} else {
		addr.Dn = raddr
	}
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr.Dn != "":
		addrType = DNADDR
		addrBody = append([]byte{byte(len(addr.Dn))}, addr.Dn...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = IPV4ADDR
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = IPV6ADDR
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return errors.New("format address error")
	}

	/**
	  +----+-----+-------+------+----------+----------+
	  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	  +----+-----+-------+------+----------+----------+
	  | 1  |  1  | X'00' |  1   | Variable |    2     |
	  +----+-----+-------+------+----------+----------+
	*/

	bodyLen := len(addrBody)
	msg := make([]byte, 6+bodyLen)
	msg[0] = VERSION5
	msg[1] = cmd
	msg[2] = 0 // RSV
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+bodyLen] = byte(addrPort >> 8)
	msg[4+bodyLen+1] = byte(addrPort & 0xff)
	_, err := w.Write(msg)
	log.Printf("send msg %s", string(msg))
	return err
}
