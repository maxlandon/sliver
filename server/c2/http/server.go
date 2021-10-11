package http

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	insecureRand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/acme/autocert"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/certs"
	"github.com/bishopfox/sliver/server/configs"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/cryptography"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/bishopfox/sliver/server/log"
	"github.com/bishopfox/sliver/util/encoders"
)

var (
	httpLog   = log.NamedLogger("c2", "http")
	accessLog = log.NamedLogger("c2", "http-access")

	ErrMissingNonce   = errors.New("nonce not found in request")
	ErrMissingOTP     = errors.New("otp code not found in request")
	ErrInvalidEncoder = errors.New("invalid request encoder")
	ErrDecodeFailed   = errors.New("failed to decode request")
	ErrDecryptFailed  = errors.New("failed to decrypt request")
)

const (
	DefaultMaxBodyLength   = 2 * 1024 * 1024 * 1024 // 2Gb
	DefaultHTTPTimeout     = time.Minute * 5
	DefaultLongPollTimeout = 20 * time.Second
	DefaultLongPollJitter  = 20 * time.Second
	minPollTimeout         = time.Second * 5
)

var (
	serverVersionHeader string
)

func init() {
	insecureRand.Seed(time.Now().UnixNano())
}

// SliverHTTPC2 - Holds refs to all the C2 objects
type SliverHTTPC2 struct {
	// Base
	HTTPServer   *http.Server
	HTTPSessions *HTTPSessions
	SliverStage  []byte // Sliver shellcode to serve during staging process
	Cleanup      func()

	// C2 profile & configuration
	profile  *models.Malleable     // All information for the targeted C2 channel
	c2Config *configs.HTTPC2Config // C2 config loaded from C2 profile

	// Operating parameters
	MaxRequestLength int
	EnforceOTP       bool
	LongPollTimeout  int64
	LongPollJitter   int64

	// Security
	tlsConfig   *tls.Config
	acmeManager *autocert.Manager
}

// NewServerFromProfile - Passing a complete or partial C2 Malleable profile, create an HTTP server,
// fill all required values (either from profile, or if missing, defaults), initialize any related
// details like TLS configurations and their associated certificates, and return the server.
//
// Profile should be ignited since it passed through the root C2Handler driver function.
// It should thus be filled with appropriate certificates based on HTTP C2 protocol used.
func NewServerFromProfile(profile *models.Malleable) (srv *SliverHTTPC2, err error) {

	// Unmarshal or generate the HTTP C2 configuration for usage.
	// If the HTTP profile is nil, a default one is returned by this function.
	httpConfig := configs.GetHTTPC2ConfigFromProfile(profile.ToProtobuf().HTTP)

	// New server
	srv = &SliverHTTPC2{
		// Implant sessions
		HTTPSessions: &HTTPSessions{
			active: map[string]*HTTPSession{},
			mutex:  &sync.RWMutex{},
		},
		// Advanced C2 Profile setup
		profile:  profile,
		c2Config: httpConfig,
	}

	// Create the underlying HTTP server
	srv.HTTPServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", profile.Hostname, profile.Port),
		Handler:      srv.router(),
		WriteTimeout: DefaultHTTPTimeout,
		ReadTimeout:  DefaultHTTPTimeout,
		IdleTimeout:  DefaultHTTPTimeout,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	// Operating parameters
	if srv.MaxRequestLength < 1024 {
		srv.MaxRequestLength = DefaultMaxBodyLength
	}
	srv.LongPollTimeout = profile.PollTimeout
	if srv.LongPollTimeout == 0 {
		srv.LongPollTimeout = int64(DefaultLongPollTimeout)
		srv.LongPollJitter = int64(DefaultLongPollJitter)
	}

	// Security: Always populate a complete TLS configuration by default.
	// It will not be used if the server is asked to serve HTTP and not HTTPS
	srv.tlsConfig = cryptography.TLSConfigFromProfile(profile)

	// Override the configuration if Let's Encrypt provisioning is asked.
	if profile.Channel == sliverpb.C2_HTTPS && profile.LetsEncrypt {
		acmeManager := certs.GetACMEManager(srv.getServerDomain())
		srv.tlsConfig = &tls.Config{
			GetCertificate: acmeManager.GetCertificate,
		}
	}

	if srv.tlsConfig.NextProtos == nil {
		srv.tlsConfig.NextProtos = []string{"http/1.1"}
	}

	return
}

// InitServer - Starts some components like ACME if needed, and register their cleanup tasks
func (s *SliverHTTPC2) InitServer(job *core.Job) (err error) {

	// conf.Domain = filepath.Base(conf.Domain) // I don't think we need this, but we do it anyways

	// Start the ACME server if needed,
	if s.profile.LetsEncrypt {
		httpLog.Infof("Attempting to fetch let's encrypt certificate for '%s' ...", s.getServerDomain())
		acmeHTTPServer := &http.Server{Addr: ":80", Handler: s.acmeManager.HTTPHandler(nil)}
		go acmeHTTPServer.ListenAndServe()

		// and register its cleanup
		job.RegisterCleanup(func() error {
			ctx, cancelACMEShutdown := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelACMEShutdown()
			return acmeHTTPServer.Shutdown(ctx)
		})
	}

	// Finally, register the HTTP server cleanup tasks
	job.RegisterCleanup(func() error {
		ctx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdown()
		return s.HTTPServer.Shutdown(ctx)
	})

	return
}

// Serve - Start the Sliver HTTP Server, according to its settings
func (s *SliverHTTPC2) Serve(job *core.Job) (err error) {

	// If the protocol is HTTP, serve without any TLS.
	if s.profile.Channel == sliverpb.C2_HTTP {
		go s.ServeHTTP(job)
	}

	// If the protocol is HTTPS, serve with TLS from ACME or Sliver config
	if s.profile.Channel == sliverpb.C2_HTTPS {
		go s.ServeHTTPS(job)
	}

	return
}

// ServeHTTPS - Start the server and make it serve with TLS configuration, either populated
// by custom Sliver certificates (from the creds store) or with ACME-fetched certificates.
func (s *SliverHTTPC2) ServeHTTPS(job *core.Job) {

	// This applies to BOTH Sliver-specific TLS or ACME-authenticated, because:
	// - If using custom certs: the TLS configuration has already been populated from a C2 Profile
	// - If ACME, we just started the ACME server that will fetch them.
	err := s.HTTPServer.ListenAndServeTLS("", "")

	// Catch any error and clean the job
	if err != nil {
		httpLog.Errorf("HTTPS listener error: %v", err)
		job.JobCtrl <- true // Cleanup all the HTTP C2 stack.
	}
}

// ServeHTTP - Start the serve and serve HTTP without TLS.
func (s *SliverHTTPC2) ServeHTTP(job *core.Job) {
	err := s.HTTPServer.ListenAndServe()
	if err != nil {
		httpLog.Errorf("HTTP listener error: %v", err)
		job.JobCtrl <- true // Cleanup all the HTTP C2 stack.
	}
	return
}

//  --------------------------------------------------------------------------------------------------------------------
// Server Configuration & Runtime values
//  --------------------------------------------------------------------------------------------------------------------

// func (s *SliverHTTPC2) LoadC2Config() *configs.HTTPC2Config {
//         if s.c2Config != nil {
//                 return s.c2Config
//         }
//         s.c2Config = configs.GetHTTPC2Config()
//         return s.c2Config
// }

func (s *SliverHTTPC2) getServerDomain() (domain string) {
	if len(strings.Split(s.profile.Domains, ",")) == 0 {
		domain = s.profile.Hostname
	} else {
		domain = strings.Split(s.profile.Domains, ",")[0]
	}
	return ""
}

func (s *SliverHTTPC2) getServerHeader() string {
	if serverVersionHeader == "" {
		switch insecureRand.Intn(1) {
		case 0:
			serverVersionHeader = fmt.Sprintf("Apache/2.4.%d (Unix)", insecureRand.Intn(48))
		default:
			serverVersionHeader = fmt.Sprintf("nginx/1.%d.%d (Ubuntu)", insecureRand.Intn(21), insecureRand.Intn(8))
		}
	}
	return serverVersionHeader
}

// DefaultRespHeaders - Configures default response headers
func (s *SliverHTTPC2) DefaultRespHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if s.c2Config.ServerConfig.RandomVersionHeaders {
			resp.Header().Set("Server", s.getServerHeader())
		}
		for _, header := range s.c2Config.ServerConfig.ExtraHeaders {
			resp.Header().Set(header.Name, header.Value)
		}
		next.ServeHTTP(resp, req)
	})
}

func (s *SliverHTTPC2) getCookieName() string {
	cookies := configs.GetHTTPC2Config().ServerConfig.Cookies
	index := insecureRand.Intn(len(cookies))
	return cookies[index]
}
func (s *SliverHTTPC2) getPollTimeout() time.Duration {
	if s.LongPollJitter < 0 {
		s.LongPollJitter = 0
	}
	min := s.LongPollTimeout
	max := s.LongPollTimeout + s.LongPollJitter
	timeout := float64(min) + insecureRand.Float64()*(float64(max)-float64(min))
	pollTimeout := time.Duration(int64(timeout))
	httpLog.Debugf("Poll timeout: %s", pollTimeout)
	if pollTimeout < minPollTimeout {
		httpLog.Warnf("Poll timeout is too short, using default minimum %v", minPollTimeout)
		pollTimeout = minPollTimeout
	}
	return pollTimeout
}

//  --------------------------------------------------------------------------------------------------------------------
// Server Security & Authentication
//  --------------------------------------------------------------------------------------------------------------------

// This filters requests that do not have a valid nonce
func (s *SliverHTTPC2) filterNonce(req *http.Request, rm *mux.RouteMatch) bool {
	nonce, err := getNonceFromURL(req.URL)
	if err != nil {
		httpLog.Warnf("Invalid nonce '%d'", nonce)
		return false // NaN
	}
	return true
}

func (s *SliverHTTPC2) filterOTP(req *http.Request, rm *mux.RouteMatch) bool {
	if s.EnforceOTP {
		httpLog.Debug("Checking for valid OTP code ...")
		otpCode, err := getOTPFromURL(req.URL)
		if err != nil {
			httpLog.Warnf("Failed to validate OTP %s", err)
			return false
		}
		valid, err := cryptography.ValidateTOTP(otpCode)
		if err != nil {
			httpLog.Warnf("Failed to validate OTP %s", err)
			return false
		}
		if valid {
			return true
		}
		return false
	} else {
		httpLog.Debug("OTP enforcement is disabled")
		return true // OTP enforcement is disabled
	}
}

func getNonceFromURL(reqURL *url.URL) (int, error) {
	qNonce := ""
	for arg, values := range reqURL.Query() {
		if len(arg) == 1 {
			qNonce = digitsOnly(values[0])
			break
		}
	}
	if qNonce == "" {
		httpLog.Warn("Nonce not found in request")
		return 0, ErrMissingNonce
	}
	nonce, err := strconv.Atoi(qNonce)
	if err != nil {
		httpLog.Warnf("Invalid nonce, failed to parse '%s'", qNonce)
		return 0, err
	}
	_, _, err = encoders.EncoderFromNonce(nonce)
	if err != nil {
		httpLog.Warnf("Invalid nonce (%s)", err)
		return 0, err
	}
	return nonce, nil
}

func getOTPFromURL(reqURL *url.URL) (string, error) {
	otpCode := ""
	for arg, values := range reqURL.Query() {
		if len(arg) == 2 {
			otpCode = digitsOnly(values[0])
			break
		}
	}
	if otpCode == "" {
		httpLog.Warn("OTP not found in request")
		return "", ErrMissingNonce
	}
	return otpCode, nil
}

func digitsOnly(value string) string {
	var buf bytes.Buffer
	for _, char := range value {
		if unicode.IsDigit(char) {
			buf.WriteRune(char)
		}
	}
	return buf.String()
}

//  --------------------------------------------------------------------------------------------------------------------
// Other Operating low-level functions
//  --------------------------------------------------------------------------------------------------------------------

func (s *SliverHTTPC2) readReqBody(httpSession *HTTPSession, resp http.ResponseWriter, req *http.Request) ([]byte, error) {
	nonce, _ := getNonceFromURL(req.URL)
	_, encoder, err := encoders.EncoderFromNonce(nonce)
	if err != nil {
		httpLog.Warnf("Request specified an invalid encoder (%d)", nonce)
		s.defaultHandler(resp, req)
		return nil, ErrInvalidEncoder
	}

	body, err := ioutil.ReadAll(&io.LimitedReader{
		R: req.Body,
		N: int64(s.MaxRequestLength),
	})
	if err != nil {
		httpLog.Warnf("Failed to read request body %s", err)
		return nil, err
	}

	data, err := encoder.Decode(body)
	if err != nil {
		httpLog.Warnf("Failed to decode body %s", err)
		s.defaultHandler(resp, req)
		return nil, ErrDecodeFailed
	}
	plaintext, err := httpSession.CipherCtx.Decrypt(data)
	if err != nil {
		httpLog.Warnf("Decryption failure %s", err)
		s.defaultHandler(resp, req)
		return nil, ErrDecryptFailed
	}
	return plaintext, err
}

func (s *SliverHTTPC2) getHTTPSession(req *http.Request) *HTTPSession {
	for _, cookie := range req.Cookies() {
		httpSession := s.HTTPSessions.Get(cookie.Value)
		if httpSession != nil {
			httpSession.ImplanConn.UpdateLastMessage()
			return httpSession
		}
	}
	return nil // No valid cookie names
}

func getRemoteAddr(req *http.Request) string {
	ipAddress := req.Header.Get("X-Real-Ip")
	if ipAddress == "" {
		ipAddress = req.Header.Get("X-Forwarded-For")
	}
	if ipAddress == "" {
		return req.RemoteAddr
	}

	// Try to parse the header as an IP address, as this is user controllable
	// input we don't want to trust it.
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		httpLog.Warn("Failed to parse X-Header as ip address")
		return req.RemoteAddr
	}
	return fmt.Sprintf("tcp(%s)->%s", req.RemoteAddr, ip.String())
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		accessLog.Infof("%s - %s - %v", getRemoteAddr(req), req.RequestURI, req.Header.Get("User-Agent"))
		next.ServeHTTP(resp, req)
	})
}

// func getHTTPTLSConfig(conf *HTTPServerConfig) *tls.Config {
//         if conf.Cert == nil || conf.Key == nil {
//                 var err error
//                 if conf.Domain != "" {
//                         conf.Cert, conf.Key, err = certs.HTTPSGenerateRSACertificate(conf.Domain)
//                 } else {
//                         conf.Cert, conf.Key, err = certs.HTTPSGenerateRSACertificate("localhost")
//                 }
//                 if err != nil {
//                         httpLog.Errorf("Failed to generate self-signed tls cert/key pair %s", err)
//                         return nil
//                 }
//         }
//         cert, err := tls.X509KeyPair(conf.Cert, conf.Key)
//         if err != nil {
//                 httpLog.Errorf("Failed to parse tls cert/key pair %s", err)
//                 return nil
//         }
//         return &tls.Config{
//                 Certificates: []tls.Certificate{cert},
//         }
// }
