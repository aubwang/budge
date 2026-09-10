package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"budge/internal/client"
	budgemcp "budge/internal/mcp"
	"budge/internal/server"
	"budge/internal/store"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/term"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "budge:", err)
		os.Exit(1)
	}
}
func secret(label string, fd int) (string, error) {
	if fd >= 0 {
		f := os.NewFile(uintptr(fd), "secret-input")
		if f == nil {
			return "", errors.New("invalid secret input descriptor")
		}
		s, e := bufio.NewReader(io.LimitReader(f, 64<<10)).ReadString('\n')
		if e != nil && e != io.EOF {
			return "", e
		}
		for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
			s = s[:len(s)-1]
		}
		return s, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("use a dedicated --*-fd input stream without a terminal")
	}
	fmt.Fprint(os.Stderr, label+": ")
	b, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), e
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: budge server|enroll|connect|mcp")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	flags := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	switch os.Args[1] {
	case "server":
		recoverRestored := flags.Bool("recover-restored", false, "invalidate all device access and undispatched requests before serving a restored database")
		dbPath := flags.String("db", "state/budge.db", "SQLite path")
		public := flags.String("url", "https://localhost:8443", "externally reachable HTTPS origin")
		deviceAddr := flags.String("device-listen", "127.0.0.1:8443", "device TLS bind address")
		ownerAddr := flags.String("owner-listen", "127.0.0.1:8080", "loopback owner bind address")
		unlockFD := flags.Int("unlock-fd", -1, "dedicated unlock input FD")
		ownerFD := flags.Int("owner-password-fd", -1, "dedicated initial owner password FD")
		if e := flags.Parse(os.Args[2:]); e != nil {
			return e
		}
		h, _, e := net.SplitHostPort(*ownerAddr)
		if e != nil || h != "127.0.0.1" {
			return errors.New("owner listener must bind 127.0.0.1")
		}
		unlock, e := secret("Server unlock secret", *unlockFD)
		if e != nil {
			return e
		}
		db, e := store.Open(*dbPath, unlock)
		if e != nil {
			return e
		}
		defer db.Close()
		var n int
		if e = db.DB.QueryRow("SELECT count(*) FROM owners").Scan(&n); e != nil {
			return e
		}
		password := ""
		if n == 0 {
			password, e = secret("Initial owner password", *ownerFD)
			if e != nil {
				return e
			}
		}
		s, e := server.New(db, *public, *ownerAddr, password)
		if e != nil {
			return e
		}
		if *recoverRestored {
			if e = s.RecoverRestored(); e != nil {
				return e
			}
		}
		tc, e := s.TLSConfig()
		if e != nil {
			return e
		}
		dl, e := net.Listen("tcp", *deviceAddr)
		if e != nil {
			return e
		}
		defer dl.Close()
		ol, e := net.Listen("tcp", *ownerAddr)
		if e != nil {
			return e
		}
		defer ol.Close()
		fmt.Fprintln(os.Stderr, "Owner UI: http://"+*ownerAddr)
		workerCtx, cancelWorker := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); s.RunWorker(workerCtx) }()
		e = serve(ctx, []net.Listener{tls.NewListener(dl, tc), ol}, []http.Handler{s.DeviceHandler(), s.OwnerHandler()})
		cancelWorker()
		<-done
		return e
	case "enroll":
		path := flags.String("identity", defaultIdentity(), "encrypted identity path")
		invFD := flags.Int("invitation-fd", -1, "dedicated invitation input FD")
		passFD := flags.Int("passphrase-fd", -1, "dedicated identity passphrase input FD")
		if e := flags.Parse(os.Args[2:]); e != nil {
			return e
		}
		if _, e := os.Stat(*path); e == nil {
			return errors.New("identity already exists")
		}
		inv, e := secret("Enrollment invitation", *invFD)
		if e != nil {
			return e
		}
		pass, e := secret("New local identity passphrase", *passFD)
		if e != nil {
			return e
		}
		if len(pass) < 12 {
			return errors.New("passphrase must have at least 12 characters")
		}
		id, e := client.Enroll(ctx, inv)
		if e != nil {
			return e
		}
		if e = client.Save(*path, pass, id); e != nil {
			return e
		}
		fmt.Fprintln(os.Stderr, "Enrolled device", id.DeviceID)
		return nil
	case "connect":
		configOnly := flags.Bool("print-opencode-config", false, "print OpenRouter routing config without starting or unlocking")
		service := flags.String("service", "openrouter", "service ID for generated config")
		socket := flags.String("socket", filepath.Join(filepath.Dir(defaultIdentity()), "connect.sock"), "private MCP connector socket")
		path := flags.String("identity", defaultIdentity(), "encrypted identity path")
		listen := flags.String("listen", "127.0.0.1:7777", "loopback connector address")
		passFD := flags.Int("passphrase-fd", -1, "dedicated identity passphrase input FD")
		if e := flags.Parse(os.Args[2:]); e != nil {
			return e
		}
		if *configOnly {
			b, e := client.OpenCodeConfig(*listen, *service)
			if e != nil {
				return e
			}
			fmt.Println(string(b))
			return nil
		}
		pass, e := secret("Local identity passphrase", *passFD)
		if e != nil {
			return e
		}
		id, e := client.Load(*path, pass)
		if e != nil {
			return e
		}
		tr, e := client.Transport(id)
		if e != nil {
			return e
		}
		defer tr.CloseIdleConnections()
		renewal, e := client.NewRenewal(id, tr)
		if e != nil {
			return e
		}
		if e = renewal.Refresh(ctx, *path, pass); e != nil {
			return e
		}
		handler, e := client.ConnectorTransport(id, *listen, tr)
		if e != nil {
			return e
		}
		l, e := net.Listen("tcp", *listen)
		if e != nil {
			return e
		}
		defer l.Close()
		fmt.Fprintln(os.Stderr, "Service URL: http://"+*listen+"/s/{service}/{path}")
		sl, e := client.ListenSocket(*socket)
		if e != nil {
			return e
		}
		defer sl.Close()
		sh := client.SocketTransport(id, tr)
		renewCtx, cancelRenew := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			ticker := time.NewTicker(time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-renewCtx.Done():
					return
				case <-ticker.C:
					if e := renewal.Refresh(renewCtx, *path, pass); e != nil {
						fmt.Fprintln(os.Stderr, "Certificate renewal needs attention:", e)
					}
				}
			}
		}()
		e = serve(ctx, []net.Listener{l, sl}, []http.Handler{handler, sh})
		cancelRenew()
		<-done
		return e
	case "mcp":
		socket := flags.String("socket", filepath.Join(filepath.Dir(defaultIdentity()), "connect.sock"), "private connector socket")
		if e := flags.Parse(os.Args[2:]); e != nil {
			return e
		}
		c, e := client.SocketClient(*socket)
		if e != nil {
			return e
		}
		defer c.CloseIdleConnections()
		return budgemcp.New(c).Run(ctx, &sdk.StdioTransport{})
	default:
		return errors.New("unknown command")
	}
}
func defaultIdentity() string {
	dir, e := os.UserConfigDir()
	if e != nil {
		return "state/device.identity"
	}
	return filepath.Join(dir, "budge", "device.identity")
}
func serve(ctx context.Context, listeners []net.Listener, handlers []http.Handler) error {
	errs := make(chan error, len(listeners))
	servers := make([]*http.Server, len(listeners))
	for i, l := range listeners {
		s := &http.Server{Handler: handlers[i], ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0)}
		servers[i] = s
		go func() { errs <- s.Serve(l) }()
	}
	select {
	case <-ctx.Done():
	case e := <-errs:
		for _, s := range servers {
			s.Close()
		}
		return e
	}
	for _, s := range servers {
		s.Close()
	}
	return nil
}
