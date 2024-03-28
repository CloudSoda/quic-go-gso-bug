package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	if len(os.Args) < 2 {
		fmt.Println("'server' or 'client' argument is required")
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "server":
		err = serverCommand()
	case "client":
		if len(os.Args) < 3 {
			err = errors.New("a host address is required")
		} else {
			err = clientCommand(os.Args[2:])
		}
	default:
		err = errors.New("specify 'server' or 'client'")
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func clientCommand(args []string) error {
	addr := args[0]
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	tr := quic.Transport{
		Conn:               udpConn,
		ConnectionIDLength: 4,
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tr.Dial(context.Background(), udpAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout: 5 * time.Minute,
	})
	if err != nil {
		return err
	}
	fmt.Println("Connected to", addr)

	go handlePings(conn)
	go handleUserInput(conn)

	select {}
}

func serverCommand() error {
	port := 4080
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return err
	}
	defer conn.Close()

	tr := &quic.Transport{
		Conn:               conn,
		ConnectionIDLength: 4,
	}

	lis, err := tr.Listen(generateTLSConfig("localhost"), &quic.Config{
		MaxIdleTimeout: 5 * time.Minute,
	})
	if err != nil {
		return err
	}
	defer lis.Close()
	func generateTLSConfig(hostnames ...string) *tls.Config {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			panic(err)
		}
	
		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			DNSNames:     hostnames,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
	
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	
		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			panic(err)
		}
	
		return &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		}
	}
	
		go handlePings(qc)
	}
}

func handleUserInput(conn quic.Connection) {
	defer conn.CloseWithError(0, "handleConn finished")

	cin := bufio.NewReader(os.Stdin)
	for {
		if _, _, err := cin.ReadLine(); err != nil {
			fmt.Printf("Reading from stdin: %v\n", err)
			return
		}

		fmt.Println("Sending ping…")
		start := time.Now()
		s, err := conn.OpenStream()
		if err != nil {
			fmt.Printf("Opening stream: %v\n", err)
			os.Exit(1)
		}
		if _, err = s.Write([]byte("ping")); err != nil {
			fmt.Printf("Writing ping: %v\n", err)
			os.Exit(1)
		}

		buf := make([]byte, 4)
		if _, err := s.Read(buf); err != nil {
			if err != io.EOF {
				fmt.Printf("Reading pong: %v\n", err)
				os.Exit(1)
			}
		}
		if string(buf) != "pong" {
			fmt.Printf("Received %v instead of pong\n", buf)
			os.Exit(1)
		}
		fmt.Println(time.Since(start))
		s.Close()
	}
}

func handlePings(conn quic.Connection) {
	for {
		s, err := conn.AcceptStream(context.Background())
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		buf := make([]byte, 4)
		if _, err := s.Read(buf); err != nil {
			fmt.Print(err)
			os.Exit(1)
		}

		if string(buf) != "ping" {
			fmt.Println("received something other than ping:", buf)
			os.Exit(1)
		}

		if _, err := s.Write([]byte("pong")); err != nil {
			fmt.Println("writing pong:", err)
			os.Exit(1)
		}
		s.Close()
	}
}

func generateTLSConfig(hostnames ...string) *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     hostnames,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
}
