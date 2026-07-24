// Command testlab-simulators runs deterministic protocol fixtures for the
// Linux-only integration lab.  It deliberately uses non-default ports so it
// can coexist with the real database containers in the same network.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"log"
	"math/big"
	"net"
	"time"
)

type tcpFixture struct {
	addr     string
	response []byte
	tls      bool
}

func main() {
	certificate := mustCertificate()
	fixtures := []tcpFixture{
		{":18080", []byte("HTTP/1.1 200 OK\r\nServer: xmap-testlab\r\nContent-Length: 2\r\n\r\nOK"), false},
		{":443", []byte("HTTP/1.1 200 OK\r\nServer: xmap-testlab\r\nContent-Length: 2\r\n\r\nOK"), true},
		{":22", []byte("SSH-2.0-OpenSSH_9.8 xmap-testlab\r\n"), false},
		{":21", []byte("220 xmap-testlab FTP server ready\r\n"), false},
		{":990", []byte("220 xmap-testlab FTPS server ready\r\n"), true},
		{":23", []byte("\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f"), false},
		{":25", []byte("220 smtp.xmap.test ESMTP Postfix\r\n"), false},
		{":465", []byte("220 smtp.xmap.test ESMTP Postfix\r\n"), true},
		{":110", []byte("+OK xmap-testlab POP3 ready\r\n"), false},
		{":995", []byte("+OK xmap-testlab POP3 ready\r\n"), true},
		{":143", []byte("* OK xmap-testlab IMAP ready\r\n"), false},
		{":993", []byte("* OK xmap-testlab IMAP ready\r\n"), true},
		{":53", dnsTCPResponse(), false},
		{":6379", []byte("-NOAUTH Authentication required.\r\n"), false},
		{":27017", []byte("xversion\x00\x00\x00\x00\x007.0.0"), false},
		{":9200", []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 43\r\n\r\n{\"name\":\"xmap\",\"version\":{\"number\":\"8.0\"}}"), false},
		{":389", []byte("0\f\x02\x01\x01a\x07\n\x01\x00\x04\x00\x04\x00"), false},
		{":636", []byte("0\f\x02\x01\x01a\x07\n\x01\x00\x04\x00\x04\x00"), true},
		{":3389", []byte("\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x0f\x08\x00\x02\x00\x00\x00"), false},
		{":5900", []byte("RFB 003.008\n"), false},
		{":11211", []byte("STAT pid 1\r\nSTAT uptime 1\r\nSTAT time 1\r\nSTAT version 1.6.0\r\nEND\r\n"), false},
		{":1883", []byte(" \x02\x00\x00"), false},
		{":5672", []byte("AMQP\x00\x00\x09\x01"), false},
		{":5060", []byte("SIP/2.0 200 OK\r\nServer: xmap-testlab\r\nContent-Length: 0\r\n\r\n"), false},
		{":554", []byte("RTSP/1.0 200 OK\r\nServer: xmap-testlab\r\n\r\n"), false},
	}
	for _, fixture := range fixtures {
		go serveTCP(fixture, certificate)
	}
	go serveUDP(":53", dnsResponse())
	go serveUDP(":161", []byte("0\x0c\x02\x01\x00\x04\x06public\xa2\x01\x00"))
	select {}
}

func serveTCP(fixture tcpFixture, certificate tls.Certificate) {
	listener, err := net.Listen("tcp", fixture.addr)
	if err != nil {
		log.Fatalf("listen %s: %v", fixture.addr, err)
	}
	if fixture.tls {
		listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}})
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = conn.Write(fixture.response)
			buf := make([]byte, 2048)
			_, _ = conn.Read(buf)
		}()
	}
}

func serveUDP(addr string, response []byte) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	buf := make([]byte, 4096)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		out := append([]byte(nil), response...)
		if n >= 2 {
			out[0], out[1] = buf[0], buf[1]
		}
		_, _ = conn.WriteTo(out, peer)
	}
}

func dnsResponse() []byte {
	return []byte{
		0x00, 0x06, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd', 0x00, 0x00, 0x10, 0x00, 0x03,
		0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x0b,
		0x0a, '9', '.', '1', '1', '.', '3', '-', 'P', '1', '2',
	}
}

func dnsTCPResponse() []byte {
	response := dnsResponse()
	frame := make([]byte, 2, len(response)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(response)))
	return append(frame, response...)
}

func mustCertificate() tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "xmap-testlab"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
