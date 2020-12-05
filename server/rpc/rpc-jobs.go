package rpc

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
	"context"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/c2"
	"github.com/bishopfox/sliver/server/certs"
	"github.com/bishopfox/sliver/server/configs"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/log"
	"github.com/bishopfox/sliver/server/route"
)

const (
	defaultMTLSPort  = 4444
	defaultDNSPort   = 53
	defaultHTTPPort  = 80
	defaultHTTPSPort = 443
)

var (
	// ErrInvalidPort - Invalid TCP port number
	ErrInvalidPort = errors.New("Invalid listener port")
)

var (
	jobLog = log.NamedLogger("c2", "jobs")
)

// GetJobs - List jobs
func (rpc *Server) GetJobs(ctx context.Context, _ *commonpb.Empty) (*clientpb.Jobs, error) {
	jobs := &clientpb.Jobs{
		Active: []*clientpb.Job{},
	}
	for _, job := range core.Jobs.All() {
		jobs.Active = append(jobs.Active, &clientpb.Job{
			ID:          uint32(job.ID),
			Name:        job.Name,
			Description: job.Description,
			Protocol:    job.Protocol,
			Port:        uint32(job.Port),
			Domains:     job.Domains,
		})
	}
	return jobs, nil
}

// KillJob - Kill a server-side job
func (rpc *Server) KillJob(ctx context.Context, kill *clientpb.KillJobReq) (*clientpb.KillJob, error) {
	job := core.Jobs.Get(int(kill.ID))
	killJob := &clientpb.KillJob{}
	var err error = nil
	if job != nil {
		job.JobCtrl <- true
		killJob.ID = uint32(job.ID)
		killJob.Success = true
		if job.PersistentID != "" {
			configs.GetServerConfig().RemoveJob(job.PersistentID)
		}
	} else {
		killJob.Success = false
		err = errors.New("Invalid Job ID")
	}
	return killJob, err
}

// StartMTLSListener - Start an MTLS listener
func (rpc *Server) StartMTLSListener(ctx context.Context, req *clientpb.MTLSListenerReq) (*clientpb.MTLSListener, error) {

	if 65535 <= req.Port {
		return nil, ErrInvalidPort
	}
	listenPort := uint16(defaultMTLSPort)
	if req.Port != 0 {
		listenPort = uint16(req.Port)
	}

	// Get session for host
	session, err := route.Routes.GetSession(req.Host)
	if err != nil {
		return nil, err
	}

	// If session is nil, start listener on server, or that we have no active routes.
	if session == nil || len(route.Routes.Active) == 0 {
		job, err := c2.StartMTLSListenerJob(req.Host, listenPort)
		if err != nil {
			return nil, err
		}

		if req.Persistent {
			cfg := &configs.MTLSJobConfig{
				Host: req.Host,
				Port: listenPort,
			}
			configs.GetServerConfig().AddMTLSJob(cfg)
			job.PersistentID = cfg.JobID
		}

		return &clientpb.MTLSListener{JobID: uint32(job.ID)}, nil
	}

	// Else, send requests to session and all nodes on route with appropriate function
	lnRoute, err := route.BuildRouteToSession(session)
	if err != nil {
		return nil, err
	}

	// Forge listener request for session, with certificate information.
	caCertPEM, certPEM, keyPEM, err := getMTLSCertificates(req.Host)
	mtlsPivotReq := &sliverpb.MTLSPivotReq{
		Host:      req.Host,
		Port:      req.Port,
		CACertPEM: caCertPEM,
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		RouteID:   lnRoute.ID,
		Request:   &commonpb.Request{SessionID: session.ID},
	}
	data, _ := proto.Marshal(mtlsPivotReq)

	// Send pivot reverse mux handler requests to all nodes, including the first node server's transport
	err = initRouteReverseHandlers(lnRoute)
	if err != nil {
		return nil, fmt.Errorf("Error sending reverse handler requests: %s", err)
	}

	// Send listener request to the last node in chain anyway.
	mtlsPivot := &sliverpb.MTLSPivot{}
	resp, err := session.Request(sliverpb.MsgNumber(mtlsPivotReq), defaultTimeout, data)
	proto.Unmarshal(resp, mtlsPivot)

	if !mtlsPivot.Success {
		return nil, fmt.Errorf("Error starting remote listener (%s): %s", session.Name, mtlsPivot.Response.Err)
	}

	// If all clear, setup job
	bind := fmt.Sprintf("%s:%d", req.Host, listenPort)
	job := &core.Job{
		ID:          core.NextJobID(),
		Name:        "mtls",
		Description: fmt.Sprintf("mutual TLS listener %s (Session: %s, ID: %d)", bind, session.Name, session.ID),
		Protocol:    "tcp",
		Port:        listenPort,
		JobCtrl:     make(chan bool),
	}

	// Setup cleanup functions (make request to all necessary implants)
	go func() {
		<-job.JobCtrl
		jobLog.Infof("Stopping mTLS listener (%d) (Session: %s, ID: %d) on %s ...", job.ID, session.Name, session.ID, bind)

		// Send request to session
		mtlsCloseReq := &sliverpb.MTLSPivotCloseReq{
			Host:    mtlsPivotReq.Host,
			Port:    mtlsPivotReq.Port,
			RouteID: mtlsPivotReq.RouteID,
		}
		data, _ := proto.Marshal(mtlsCloseReq)

		mtlsClose := &sliverpb.MTLSPivotClose{}
		resp, err := session.Request(sliverpb.MsgNumber(mtlsCloseReq), defaultTimeout, data)
		proto.Unmarshal(resp, mtlsClose)

		if !mtlsPivot.Success {
			jobLog.Errorf("Error removing remote listener (%s): %s", session.Name, mtlsClose.Response.Err)
		}

		// Send request to intermediate nodes
		if len(lnRoute.Nodes) > 1 {
			err = removeRouteReverseHandlers(lnRoute)
			if err != nil {
				jobLog.Errorf("Error removing reverse mux handlers on route: %s", err)
			}
		}

		core.Jobs.Remove(job)
	}()
	core.Jobs.Add(job)

	return &clientpb.MTLSListener{JobID: uint32(job.ID)}, nil
}

// When we want to start a listener on an implant, we forge new certificates for this host.
func getMTLSCertificates(host string) (caCert, certPEM, keyPEM []byte, err error) {

	// Create certificates if they don't exist.
	_, _, err = certs.GetCertificate(certs.C2ServerCA, certs.ECCKey, host)
	if err != nil {
		certs.C2ServerGenerateECCCertificate(host)
	}

	// Get CA Certificate
	caCert, _, err = certs.GetCertificateAuthorityPEM(certs.ImplantCA)
	if err != nil {
		return nil, nil, nil, err
	}

	// Query certificates again
	certPEM, keyPEM, err = certs.GetCertificate(certs.C2ServerCA, certs.ECCKey, host)
	if err != nil {
		return nil, nil, nil, err
	}

	return
}

// For each intermediate node in a route, we add a handler to handle reverse listener connections.
func initRouteReverseHandlers(route *sliverpb.Route) (err error) {

	// Add handler to the first node Transport's, for automatic registration of session.
	servNode := c2.Transports.GetBySession(route.Nodes[0].ID)
	go servNode.HandleSession(route)

	// Cutoff the chain at each node
	next := *route

	if len(next.Nodes) > 1 {
		// We never count the last node, as it will receive a special request with certificate information.
		for _, node := range next.Nodes[:(len(next.Nodes) - 1)] {

			reverseOpenReq := &sliverpb.PivotReverseRouteOpenReq{
				Request: &commonpb.Request{SessionID: node.ID},
				Route:   &next,
			}
			data, _ := proto.Marshal(reverseOpenReq)

			session := core.Sessions.Get(node.ID)

			reverseOpen := &sliverpb.PivotReverseRouteOpen{}
			resp, err := session.Request(sliverpb.MsgNumber(reverseOpenReq), defaultTimeout, data)
			if err != nil {
				return err
			}
			proto.Unmarshal(resp, reverseOpen)

			if reverseOpen.Success == false {
				return errors.New(reverseOpen.Response.Err)
			}

			next.Nodes = next.Nodes[1:]
		}
	}

	return
}

// Same as initRouteReverseHandlers, but for removing the reverse handlers.
func removeRouteReverseHandlers(r *sliverpb.Route) (err error) {

	// Cutoff the chain at each node
	next := *r

	// We never count the last node, as it will receive a special request with certificate information.
	for _, node := range next.Nodes[:(len(next.Nodes) - 1)] {

		reverseCloseReq := &sliverpb.PivotReverseRouteCloseReq{
			Request: &commonpb.Request{SessionID: node.ID},
			Route:   &next,
		}
		data, _ := proto.Marshal(reverseCloseReq)

		session := core.Sessions.Get(node.ID)

		reverseClose := &sliverpb.PivotReverseRouteClose{}
		resp, err := session.Request(sliverpb.MsgNumber(reverseCloseReq), defaultTimeout, data)
		if err != nil {
			return err
		}
		proto.Unmarshal(resp, reverseClose)

		if reverseClose.Success == false {
			return errors.New(reverseClose.Response.Err)
		}

		next.Nodes = next.Nodes[1:]
	}
	return
}

// StartDNSListener - Start a DNS listener TODO: respect request's Host specification
func (rpc *Server) StartDNSListener(ctx context.Context, req *clientpb.DNSListenerReq) (*clientpb.DNSListener, error) {
	if 65535 <= req.Port {
		return nil, ErrInvalidPort
	}
	listenPort := uint16(defaultDNSPort)
	if req.Port != 0 {
		listenPort = uint16(req.Port)
	}

	job, err := c2.StartDNSListenerJob(req.Domains, req.Canaries, listenPort)
	if err != nil {
		return nil, err
	}

	if req.Persistent {
		cfg := &configs.DNSJobConfig{
			Domains:  req.Domains,
			Port:     listenPort,
			Canaries: req.Canaries,
			Host:     req.Host,
		}
		configs.GetServerConfig().AddDNSJob(cfg)
		job.PersistentID = cfg.JobID
	}

	return &clientpb.DNSListener{JobID: uint32(job.ID)}, nil
}

// StartHTTPSListener - Start an HTTPS listener
func (rpc *Server) StartHTTPSListener(ctx context.Context, req *clientpb.HTTPListenerReq) (*clientpb.HTTPListener, error) {

	if 65535 <= req.Port {
		return nil, ErrInvalidPort
	}
	listenPort := uint16(defaultHTTPSPort)
	if req.Port != 0 {
		listenPort = uint16(req.Port)
	}

	conf := &c2.HTTPServerConfig{
		Addr:    fmt.Sprintf("%s:%d", req.Host, listenPort),
		LPort:   listenPort,
		Secure:  true,
		Domain:  req.Domain,
		Website: req.Website,
		Cert:    req.Cert,
		Key:     req.Key,
		ACME:    req.ACME,
	}
	job, err := c2.StartHTTPListenerJob(conf)
	if err != nil {
		return nil, err
	}

	if req.Persistent {
		cfg := &configs.HTTPJobConfig{
			Domain:  req.Domain,
			Host:    req.Host,
			Port:    listenPort,
			Secure:  true,
			Website: req.Website,
			Cert:    req.Cert,
			Key:     req.Key,
			ACME:    req.ACME,
		}
		configs.GetServerConfig().AddHTTPJob(cfg)
		job.PersistentID = cfg.JobID
	}

	return &clientpb.HTTPListener{JobID: uint32(job.ID)}, nil
}

// StartHTTPListener - Start an HTTP listener
func (rpc *Server) StartHTTPListener(ctx context.Context, req *clientpb.HTTPListenerReq) (*clientpb.HTTPListener, error) {
	if 65535 <= req.Port {
		return nil, ErrInvalidPort
	}
	listenPort := uint16(defaultHTTPPort)
	if req.Port != 0 {
		listenPort = uint16(req.Port)
	}

	conf := &c2.HTTPServerConfig{
		Addr:    fmt.Sprintf("%s:%d", req.Host, listenPort),
		LPort:   listenPort,
		Domain:  req.Domain,
		Website: req.Website,
		Secure:  false,
		ACME:    false,
	}
	job, err := c2.StartHTTPListenerJob(conf)
	if err != nil {
		return nil, err
	}

	if req.Persistent {
		cfg := &configs.HTTPJobConfig{
			Domain:  req.Domain,
			Host:    req.Host,
			Port:    listenPort,
			Secure:  false,
			Website: req.Website,
		}
		configs.GetServerConfig().AddHTTPJob(cfg)
		job.PersistentID = cfg.JobID
	}

	return &clientpb.HTTPListener{JobID: uint32(job.ID)}, nil
}
