package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/viper"
)

var port = flag.Int("p", 9000, "Listen Port")
var Users = make(map[string]string)

func init() {
	viper.SetConfigFile("./user.yaml")
	err := viper.ReadInConfig()
	if err != nil {
		log.Printf("Error Read Config file: %v\n", err)
		os.Exit(1)
	}
	users := viper.GetStringMapString("users")
	for user, paswd := range users {
		rawString := fmt.Sprintf("%s:%s", user, paswd)
		encodedString := base64.StdEncoding.EncodeToString([]byte(rawString))
		Users[encodedString] = user
	}
}

func main() {
	flag.Parse()
	addr := fmt.Sprintf(":%d", *port)
	l, err := net.Listen("tcp", addr)
	log.Printf("Start Listen on %s ......\n", addr)
	if err != nil {
		log.Panic(err)
	}
	for {
		client, err := l.Accept()
		if err != nil {
			log.Panicf("Error Accept Connection: %s\n", err)
		}

		go handleRequest(client)
	}
}

func handleRequest(c net.Conn) {
	var user string
	if c == nil {
		return
	}
	defer c.Close()

	var b = make([]byte, 4096)
	n, err := c.Read(b[:])
	if err != nil && err.Error() != "EOF" {
		log.Printf("Error Read Connection Bytes: %s\n", err)
		return
	}

	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(b[:n])))
	mimeHeader, _ := tp.ReadMIMEHeader()
	credential := mimeHeader.Get("Proxy-Authorization")
	if credential == "" {
		c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Authorization Required\"\r\n\r\n"))
		return
	} else {
		var ok bool
		ok, user = validUser(credential)
		if !ok {
			c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Invalid User\"\r\n\r\n"))
			return
		}

	}

	var method, host, address string
	fmt.Sscanf(string(b[:bytes.IndexByte(b[:], '\n')]), "%s%s", &method, &host)
	hostPortURL, err := url.Parse(host)
	if err != nil {
		log.Printf("Error hostPortURL Parse [%s]: %s\n", host, err)
		return
	}

	// rawURL, _ := json.Marshal(hostPortURL)
	// fmt.Println(string(rawURL))
	// if hostPortURL.Opaque == "443" {
	// 	address = hostPortURL.Scheme + ":443"
	// } else {
	// 	if strings.Index(hostPortURL.Host, ":") == -1 {
	// 		address = hostPortURL.Host + ":80"
	// 	} else {
	// 		address = hostPortURL.Host
	// 	}
	// }
	if hostPortURL.Scheme == "http" {
		if strings.Contains(hostPortURL.Host, ":") {
			address = hostPortURL.Host
		} else {
			address = hostPortURL.Host + ":" + "80"
		}
	} else {
		address = hostPortURL.Scheme + ":" + hostPortURL.Opaque
	}

	server, err := net.Dial("tcp", address)
	if err != nil {
		log.Printf("Error Dial Host %s : %s\n", address, err)
		return
	}
	if method == "CONNECT" {
		fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	} else {
		server.Write(b[:n])
	}

	go io.Copy(server, c)
	io.Copy(c, server)
	log.Printf("%s[%s]\tVisit\t%s\n", user, c.RemoteAddr().String(), host)
}

func validUser(credential string) (bool, string) {
	s := strings.Split(credential, " ")
	if len(s) != 2 {
		return false, ""
	}
	if user, ok := Users[s[1]]; ok {
		return true, user
	}
	return false, ""
}
