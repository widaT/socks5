package socks5

import (
	"context"
	"io"
	"sync"
	"testing"
)

type pipeConn struct {
	reader       *io.PipeReader
	writer       *io.PipeWriter
	writeBlocker sync.Mutex
}

func (p *pipeConn) Read(b []byte) (int, error) {
	return p.reader.Read(b)
}

func (p *pipeConn) Write(b []byte) (int, error) {
	p.writeBlocker.Lock()
	defer p.writeBlocker.Unlock()
	return p.writer.Write(b)
}

func (p *pipeConn) Close() error {
	p.reader.Close()
	return p.writer.Close()
}

func testConn() (io.ReadWriteCloser, io.ReadWriteCloser) {
	read1, write1 := io.Pipe()
	read2, write2 := io.Pipe()
	conn1 := &pipeConn{reader: read1, writer: write2}
	conn2 := &pipeConn{reader: read2, writer: write1}
	return conn1, conn2
}

func TestHandleSock5(t *testing.T) {
	server, client := testConn()
	defer server.Close()
	defer client.Close()
	go func() {
		if err := HandleSocks5(context.Background(), server); err != nil {
			t.Fatal(err)
		}

	}()
	if _, err := HandleSocks5Client(context.Background(), client, "localhost", 22); err != nil {
		t.Fatal(err)
	}
}
