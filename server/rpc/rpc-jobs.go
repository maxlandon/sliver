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

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/server/c2"
	"github.com/bishopfox/sliver/server/configs"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
)

const (
	defaultMTLSPort    = 4444
	defaultWGPort      = 53
	defaultWGNPort     = 8888
	defaultWGKeyExPort = 1337
	defaultDNSPort     = 53
	defaultHTTPPort    = 80
	defaultHTTPSPort   = 443
)

var (
	// ErrInvalidPort - Invalid TCP port number
	ErrInvalidPort = errors.New("Invalid listener port")
)

// GetJobs - List jobs
func (rpc *Server) GetJobs(ctx context.Context, _ *commonpb.Empty) (*clientpb.Jobs, error) {
	jobs := &clientpb.Jobs{
		Active: []*clientpb.Job{},
	}
	for _, job := range core.Jobs.All() {
		jobs.Active = append(jobs.Active, job.ToProtobuf())
	}
	return jobs, nil
}

// KillJob - Kill a server-side job
func (rpc *Server) KillJob(ctx context.Context, kill *clientpb.KillJobReq) (*clientpb.KillJob, error) {

	var job *core.Job
	for _, active := range core.Jobs.All() {
		if core.GetShortID(active.ID.String()) == kill.ID {
			job = active
		}
	}

	killJob := &clientpb.KillJob{}
	var err error = nil
	if job != nil {
		job.JobCtrl <- true
		killJob.ID = job.ID.String()
		killJob.Success = true
		if job.Profile.Persistent {
			configs.GetServerConfig().RemoveJob(job.ID.String())
		}
	} else {
		killJob.Success = false
		err = errors.New("Invalid Job ID")
	}

	// Delete persistent jobs for their appropriate context, if they exist
	if job.Profile != nil && job.Profile.Persistent {
		// If job is a server job
		if job.SessionName == "" {
			configs.GetServerConfig().RemoveJob(job.ID.String())
		}
		// If job was running on a session
		dbJob, err := db.JobByID(job.ID.String())
		if err != nil {
			return killJob, err // TODO: Should get rid of that
		}
		err = db.Session().Delete(dbJob).Error
	}

	return killJob, err
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

	_, err := c2.StartDNSListenerJob(req.Host, listenPort, req.Domains, req.Canaries)
	if err != nil {
		return nil, err
	}

	// if req.Persistent {
	//         cfg := &configs.DNSJobConfig{
	//                 Domains:  req.Domains,
	//                 Host:     req.Host,
	//                 Port:     listenPort,
	//                 Canaries: req.Canaries,
	//         }
	//         configs.GetServerConfig().AddDNSJob(cfg)
	//         job.PersistentID = cfg.JobID
	// }

	return &clientpb.DNSListener{JobID: 0}, nil
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
	_, err := c2.StartHTTPListenerJob(conf)
	if err != nil {
		return nil, err
	}

	// if req.Persistent {
	//         cfg := &configs.HTTPJobConfig{
	//                 Domain:  req.Domain,
	//                 Host:    req.Host,
	//                 Port:    listenPort,
	//                 Secure:  true,
	//                 Website: req.Website,
	//                 Cert:    req.Cert,
	//                 Key:     req.Key,
	//                 ACME:    req.ACME,
	//         }
	//         configs.GetServerConfig().AddHTTPJob(cfg)
	//         job.PersistentID = cfg.JobID
	// }

	return &clientpb.HTTPListener{JobID: 0}, nil
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
	_, err := c2.StartHTTPListenerJob(conf)
	if err != nil {
		return nil, err
	}

	// if req.Persistent {
	//         cfg := &configs.HTTPJobConfig{
	//                 Domain:  req.Domain,
	//                 Host:    req.Host,
	//                 Port:    listenPort,
	//                 Secure:  false,
	//                 Website: req.Website,
	//         }
	//         configs.GetServerConfig().AddHTTPJob(cfg)
	//         job.PersistentID = cfg.JobID
	// }

	return &clientpb.HTTPListener{JobID: 0}, nil
}
