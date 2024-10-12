package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/PCJones/nntp-proxy/config"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"strings"
)

var (
	cfg                config.Configuration
	backendConnections map[string]int
)

type session struct {
	UserConnection    net.Conn
	backendConnection net.Conn
	command           string
	selectedBackend   *config.SelectedBackend
}

// Utils
func HashPassword(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes)
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func isCommandAllowed(command string) bool {
	for _, elem := range cfg.Frontend.FrontendAllowedCommands {
		if strings.ToLower(elem.FrontendCommand) == strings.ToLower(command) {
			return true
		}
	}
	return false
}

func LoadConfig(path string) config.Configuration {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("Config File Missing. ", err)
	}

	var configType config.Configuration
	err = json.Unmarshal(file, &configType)
	if err != nil {
		log.Fatal("Config Parse Error: ", err)
	}

	return configType
}

// Utils

// HTTP HANDLE

func httpHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	for _, elem := range cfg.Backend {
		fmt.Fprintf(w, "%v - %v / %v\n", elem.BackendName, backendConnections[elem.BackendName], elem.BackendConns)
	}
}

// HTTP HANDLE

func main() {

	cfg = LoadConfig("/config/config.json")

	backendConnections = make(map[string]int)

	for _, elem := range cfg.Backend {
		backendConnections[elem.BackendName] = 0
	}

	var l net.Listener

	http.HandleFunc("/backendStatus", httpHandler)
	go http.ListenAndServe(cfg.Frontend.FrontendHTTPAddr+":"+cfg.Frontend.FrontendHTTPPort, nil)

	if cfg.Frontend.FrontendTLS {

		// New var for error
		var err error

		// try to load cert pair
		cer, err := tls.LoadX509KeyPair(cfg.Frontend.FrontendTLSCert, cfg.Frontend.FrontendTLSKey)

		if err != nil {
			log.Printf("%v", err)
			return
		}

		// Set certs
		tlsConf := &tls.Config{Certificates: []tls.Certificate{cer}}

		// Listen for incoming TLS connections.
		l, err = tls.Listen("tcp", cfg.Frontend.FrontendAddr+":"+cfg.Frontend.FrontendPort, tlsConf)

		if err != nil {
			log.Printf("%v", err)
			os.Exit(1)
		}

		log.Printf("[TLS] Listening on %v:%v", cfg.Frontend.FrontendAddr, cfg.Frontend.FrontendPort)

	} else {

		// New var for error
		var err error

		// Listen for incoming connections.
		l, err = net.Listen("tcp", cfg.Frontend.FrontendAddr+":"+cfg.Frontend.FrontendPort)

		if err != nil {
			log.Printf("%v", err)
			os.Exit(1)
		}

		log.Printf("[PLAIN - DO NOT USE PROD!] Listening on %v:%v", cfg.Frontend.FrontendAddr, cfg.Frontend.FrontendPort)
	}

	// Close the listener when the application closes.
	defer l.Close()

	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go handleRequest(conn)
	}
}

func (s *session) dispatchCommand() {

	log.Printf("[Dispatch] Command : %v", s.command)

	cmd := strings.Split(s.command, " ")

	args := []string{}

	if len(cmd) > 1 {
		args = cmd[1:]
	}

	if strings.ToLower(cmd[0]) == "authinfo" {
		s.handleAuth(args)
	} else {
		if isCommandAllowed(strings.ToLower(cmd[0])) {
			s.handleRequests()
		} else {
			t := textproto.NewConn(s.UserConnection)

			t.PrintfLine("502 %s not allowed", cmd[0])
			return
		}

	}
}

func (s *session) handleRequests() {
	if s.backendConnection != nil {

		s.backendConnection.Write([]byte(s.command + "\n"))

		go io.Copy(s.backendConnection, s.UserConnection)
		io.Copy(s.UserConnection, s.backendConnection)
	}
}

func (s *session) handleAuthorization(user string, password string) bool {
	for _, elem := range cfg.Users {
		if elem.Username == user && CheckPasswordHash(password, elem.Password) {
			return true
		}
	}
	return false
}

func (s *session) handleAuth(args []string) {
	t := textproto.NewConn(s.UserConnection)

	if len(args) < 2 {
		t.PrintfLine("502 Unknown Syntax!")
		return
	}

	if strings.ToLower(args[0]) != "user" {
		t.PrintfLine("502 Unknown Syntax!")
		return
	}

	t.PrintfLine("381 Continue")

	a, _ := t.ReadLine()
	parts := strings.SplitN(a, " ", 3)

	if strings.ToLower(parts[0]) != "authinfo" || strings.ToLower(parts[1]) != "pass" {
		t.PrintfLine("502 Unknown Syntax!")
		return
	}

	if s.handleAuthorization(args[1], parts[2]) {
		selectedBackend := &config.SelectedBackend{}
		for _, elem := range cfg.Backend {

			if backendConnections[elem.BackendName] < elem.BackendConns {
				selectedBackend.BackendName = elem.BackendName
				selectedBackend.BackendAddr = elem.BackendAddr
				selectedBackend.BackendPort = elem.BackendPort
				selectedBackend.BackendTLS = elem.BackendTLS
				selectedBackend.BackendUser = elem.BackendUser
				selectedBackend.BackendPass = elem.BackendPass

				backendConnections[elem.BackendName] += 1
				break
			} else {
				continue
			}
		}

		if len(selectedBackend.BackendAddr) == 0 && len(selectedBackend.BackendPort) == 0 {
			t.PrintfLine("502 NO free backend connection!")
			return
		}

		var conn net.Conn
		var err error

		if selectedBackend.BackendTLS {

			conf := &tls.Config{
				InsecureSkipVerify: true,
			}

			conn, err = tls.Dial("tcp", selectedBackend.BackendAddr+":"+selectedBackend.BackendPort, conf)

			if err != nil {
				log.Printf("%v", err)
				log.Printf("%v:%v", selectedBackend.BackendAddr, selectedBackend.BackendPort)
				return
			}

		} else {
			// New backend connection to upstream NNTP
			conn, err = net.Dial("tcp", selectedBackend.BackendAddr+":"+selectedBackend.BackendPort)

			if err != nil {
				log.Printf("%v", err)
				log.Printf("%v:%v", selectedBackend.BackendAddr, selectedBackend.BackendPort)
				return
			}
		}

		c := textproto.NewConn(conn)

		_, _, err = c.ReadCodeLine(200)
		if err != nil {
			return
		}

		err = c.PrintfLine("authinfo user %s", selectedBackend.BackendUser)

		if err != nil {
			return
		}

		_, _, err = c.ReadCodeLine(381)
		if err != nil {
			return
		}

		err = c.PrintfLine("authinfo pass %s", selectedBackend.BackendPass)
		if err != nil {
			return
		}
		_, _, err = c.ReadCodeLine(281)

		if err == nil {
			t.PrintfLine("281 Welcome")
			s.backendConnection = conn
			s.selectedBackend = selectedBackend
			log.Printf("[CONN] Connecting to Backend: %v", selectedBackend.BackendName)

			return
		} else {
			log.Printf("%v", err)
			backendConnections[selectedBackend.BackendName] -= 1
			t.PrintfLine("502 Backend AUTH Failed!")
			return
		}

	} else {
		t.PrintfLine("502 AUTH FAILED!")
	}
}

// Handles incoming requests.
func handleRequest(conn net.Conn) {

	c := textproto.NewConn(conn)

	sess := &session{
		conn,
		nil,
		"",
		nil,
	}

	c.PrintfLine("200 Welcome to NNTP Proxy!")

	for {
		l, err := c.ReadLine()
		if err != nil {
			if sess.selectedBackend != nil && len(sess.selectedBackend.BackendName) > 0 {
				backendConnections[sess.selectedBackend.BackendName] -= 1
				log.Printf("[CONN] Dropping Backend Connection: %v", sess.selectedBackend.BackendName)
			} else {
				log.Printf("[CONN] Error dropping Backend Connection cause selectedBackend is nil")
				log.Printf("%v", sess)
				sess.selectedBackend = nil

			}

			conn.Close()
			return

		}

		sess.command = l
		sess.dispatchCommand()
	}

}
