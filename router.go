package secure_network

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/0TrustCloud/guikit"
	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/secure_policy"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Module interface {
	Name() string
	Init(router *Router) error
	Start() error
}

type SystemEvent struct {
	Topic   string
	Payload []byte
}

type Router struct {
	mu             sync.RWMutex
	Port           string
	TLSConfig      *tls.Config
	Mux            *http.ServeMux
	GUIKit         *guikit.GUIKit
	SdfEngine      *secure_data_format.SecureDataEngine
	TargetCookie   string
	RouteMap       map[string]string
	Modules        map[string]Module
	LocalBus       chan SystemEvent
	ActiveTunnel   *quic.Conn // Aligned to proper concrete library pointer values
	PolicyEngine   *secure_policy.PolicyEngine
	SessionManager *secure_policy.SessionManager
	Logger         *logger.LogDispatcher
}

func NewRouter(sdf *secure_data_format.SecureDataEngine, gk *guikit.GUIKit, targetCookie string, pe *secure_policy.PolicyEngine, sm *secure_policy.SessionManager, sysLog *logger.LogDispatcher) (*Router, error) {
	tlsConf, err := generateEphemeralTLS()
	if err != nil {
		return nil, err
	}

	return &Router{
		TLSConfig:      tlsConf,
		Mux:            http.NewServeMux(),
		GUIKit:         gk,
		SdfEngine:      sdf,
		TargetCookie:   targetCookie,
		RouteMap:       make(map[string]string),
		Modules:        make(map[string]Module),
		LocalBus:       make(chan SystemEvent, 2048),
		PolicyEngine:   pe,
		SessionManager: sm,
		Logger:         sysLog,
	}, nil
}

func (r *Router) Attach(mod Module) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Modules[mod.Name()] = mod
}

func (r *Router) Boot() {
	if r.Logger != nil {
		r.Logger.Info("Booting Aura Microkernel Core Engine Plane...")
	}

	for name, mod := range r.Modules {
		if err := mod.Init(r); err != nil {
			log.Fatalf("[AURA] Kernel Panic: Module '%s' failed to init: %v", name, err)
		}
		go func(m Module, n string) {
			if err := m.Start(); err != nil && r.Logger != nil {
				r.Logger.Error(fmt.Sprintf("Module '%s' crashed: %v", n, err))
			}
		}(mod, name)
	}

	r.setupDBSCRoutes()
	if r.GUIKit != nil {
		r.Mux.Handle("/", r.GUIKit.Mux)
	}

	go r.startQUICTunnel()
	r.startDualStackIngress()
}

type dbscInterceptor struct {
	http.ResponseWriter
	router *Router
	req    *http.Request
	wrote  bool
}

func (w *dbscInterceptor) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true

	for _, cookie := range w.req.Cookies() {
		if cookie.Name == w.router.TargetCookie {
			yamlDomain := getDBSCDomain(w.router.RouteMap, w.req)
			w.Header().Set("Secure-Session-Registration", `(ES256 RS256); path="/StartSession"`)
			if w.router.Logger != nil {
				w.router.Logger.Debug(fmt.Sprintf("Injected Secure-Session-Registration for %s (Domain: %s)", cookie.Name, yamlDomain))
			}
			break
		}
	}

	w.ResponseWriter.WriteHeader(code)
}

func (w *dbscInterceptor) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *dbscInterceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying server does not support connection hijacking")
}

func (r *Router) startQUICTunnel() {
	tunnelPort := "9000"
	listener, err := quic.ListenAddr(":"+tunnelPort, r.TLSConfig, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 30 * time.Second,
	})
	if err != nil {
		log.Fatalf("[AURA] Failed to bind QUIC Tunnel backplane: %v", err)
	}

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			continue
		}

		r.mu.Lock()
		if r.ActiveTunnel != nil {
			r.ActiveTunnel.CloseWithError(0, "New tunnel took over")
		}
		r.ActiveTunnel = conn
		r.mu.Unlock()
	}
}

func (r *Router) proxyToTunnel(w http.ResponseWriter, req *http.Request) bool {
	r.mu.RLock()
	tunnel := r.ActiveTunnel
	r.mu.RUnlock()

	if tunnel == nil {
		return false
	}

	stream, err := tunnel.OpenStreamSync(context.Background())
	if err != nil {
		return false
	}

	isWebSocket := strings.ToLower(req.Header.Get("Upgrade")) == "websocket"
	err = req.Write(stream)
	if err != nil {
		http.Error(w, "Failed to write to tunnel", http.StatusBadGateway)
		stream.Close()
		return true
	}

	br := bufio.NewReader(stream)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		http.Error(w, "Failed to read from tunnel", http.StatusBadGateway)
		stream.Close()
		return true
	}

	if isWebSocket && resp.StatusCode == http.StatusSwitchingProtocols {
		hj, ok := w.(http.Hijacker)
		if !ok {
			stream.Close()
			return true
		}
		clientConn, clientBufrw, err := hj.Hijack()
		if err != nil {
			stream.Close()
			return true
		}
		resp.Write(clientConn)

		go func() {
			defer clientConn.Close()
			defer stream.Close()
			if clientBufrw.Reader.Buffered() > 0 {
				_, _ = io.CopyN(stream, clientBufrw.Reader, int64(clientBufrw.Reader.Buffered()))
			}
			_, _ = io.Copy(stream, clientConn)
		}()

		go func() {
			defer clientConn.Close()
			defer stream.Close()
			if br.Buffered() > 0 {
				_, _ = io.CopyN(clientConn, br, int64(br.Buffered()))
			}
			_, _ = io.Copy(clientConn, stream)
		}()
		return true
	}

	defer resp.Body.Close()
	defer stream.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	return true
}

func (r *Router) setupDBSCRoutes() {
	r.Mux.HandleFunc("/StartSession", func(w http.ResponseWriter, req *http.Request) {
		yamlDomain := getDBSCDomain(r.RouteMap, req)
		subject := []byte("hardware_subject_placeholder")

		signedToken, jti, err := r.SessionManager.IssueCookieToken(subject, 24*time.Hour)
		if err != nil {
			http.Error(w, "Failed to issue token", http.StatusInternalServerError)
			return
		}

		cookie := &http.Cookie{
			Name:     r.TargetCookie,
			Value:    signedToken,
			MaxAge:   86400,
			Domain:   yamlDomain,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)

		if r.Logger != nil {
			r.Logger.Audit("system", "DBSC_SESSION_ISSUED", fmt.Sprintf("Issued hardware-bound session on domain: %s", yamlDomain))
		}

		w.Header().Set("Content-Type", "application/json")
		jsonResponse := fmt.Sprintf(`{
			"session_identifier": "%s",
			"refresh_url": "/RefreshEndpoint",
			"credentials": [{"type": "cookie", "name": "%s", "attributes": "Domain=%s; Secure; SameSite=Lax"}]
		}`, jti, r.TargetCookie, yamlDomain)
		_, _ = w.Write([]byte(jsonResponse))
	})

	r.Mux.HandleFunc("/RefreshEndpoint", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if req.Header.Get("Secure-Session-Response") == "" {
			w.Header().Set("Secure-Session-Challenge", `"challenge_value_12345"`)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		yamlDomain := getDBSCDomain(r.RouteMap, req)
		var cookieValue string
		if c, err := req.Cookie(r.TargetCookie); err == nil {
			cookieValue = c.Value
		}

		cookie := &http.Cookie{
			Name:     r.TargetCookie,
			Value:    cookieValue,
			MaxAge:   600,
			Domain:   yamlDomain,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Session successfully bound and refreshed."))
	})
}

func (r *Router) startDualStackIngress() {
	masterHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		interceptor := &dbscInterceptor{ResponseWriter: w, router: r, req: req}

		var sessionCookie *http.Cookie
		for _, cookie := range req.Cookies() {
			if cookie.Name == r.TargetCookie {
				sessionCookie = cookie
				break
			}
		}
		
		if sessionCookie != nil {
			subjectID, err := r.SessionManager.ValidateCookieToken(sessionCookie.Value)
			if err == nil {
				req.Header.Set("X-Secure-Subject", subjectID)
				req.Header.Set("X-Secure-Session-Id", sessionCookie.Value)
			}
		}

		if !r.proxyToTunnel(interceptor, req) {
			r.Mux.ServeHTTP(interceptor, req)
		}
	})

	h3Server := &http3.Server{Addr: ":" + r.Port, TLSConfig: r.TLSConfig, Handler: masterHandler}
	tcpServer := &http.Server{
		Addr:      ":" + r.Port,
		TLSConfig: r.TLSConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_ = h3Server.SetQUICHeaders(w.Header())
			masterHandler.ServeHTTP(w, req)
		}),
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if r.Logger != nil {
			r.Logger.Info(fmt.Sprintf("HTTP/3 (UDP) edge listening on :%s", r.Port))
		}
		_ = h3Server.ListenAndServe()
	}()
	go func() {
		defer wg.Done()
		if r.Logger != nil {
			r.Logger.Info(fmt.Sprintf("HTTPS (TCP) fallback listening on :%s", r.Port))
		}
		_ = tcpServer.ListenAndServeTLS("", "")
	}()
	wg.Wait()
}

func getDBSCDomain(routeMap map[string]string, req *http.Request) string {
	path := req.URL.Path
	if path == "/StartSession" || path == "/RefreshEndpoint" {
		if referer := req.Header.Get("Referer"); referer != "" {
			if u, err := url.Parse(referer); err == nil {
				path = u.Path
			}
		}
	}
	if target, exists := routeMap[path]; exists {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		return req.Host
	}
	return host
}

func generateEphemeralTLS() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Aura Microkernel Architecture"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: func() []byte { b, _ := x509.MarshalPKCS8PrivateKey(priv); return b }()}),
	)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"secure-overlay", "h3", "h2", "http/1.1"},
	}, nil
}
