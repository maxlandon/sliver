package c2

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
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/gofrs/uuid"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/comm"
	"github.com/bishopfox/sliver/server/configs"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/bishopfox/sliver/server/log"
)

var (
	jobLog = log.NamedLogger("c2", "jobs")
)

func init() {
	// VERY IMPORTANT: to avoid circular imports we map the function
	// in this package to the core package, so that the handlers package
	// can start persistent jobs upon a session registration process.
	core.StartPersistentSessionJobs = StartPersistentSessionJobs

	// For the same reason of avoiding circular imports, we assign
	// a function that automatically cleans up the transports set at
	// runtime for a session. Called when the session is killed or dies (only).
	// core.CleanupSessionTransports = CleanupSessionTransports
}

// NewHandlerJob - Create a new handler job based on the current C2 profile and the session context.
// This returns a job that is both completely fulfilled with relevant information, as well as populated
// with needed job control channels, which can be optionaly used when your C2 stack needs such for goroutine control.
//
// NOTES:
// - The job is NOT started, nor its order value initialized: the function InitHandlerJob will be called AFTER
//   your C2 stack has been started, and if it has done so successfully, then the job will be registered.
//
// - The handler job should, normally/in most cases, rest on a net.Listener running somewhere either on the session
//   or on the server. This listener is automatically closed on job kill. You are free to use it or not: it won't have
//   an impact on the overall C2 setup/usage workflow.
func NewHandlerJob(profile *models.C2Profile, session *core.Session) (job *core.Job, ln net.Listener) {

	// Base elements applying for all jobs, no matter where they run
	var host string
	if profile.Port > 0 {
		host = fmt.Sprintf("%s:%d%s", profile.Hostname, profile.Port, profile.Path)
	} else {
		host = fmt.Sprintf("%s%s", profile.Hostname, profile.Path)
	}

	// Base job with these info.
	id, _ := uuid.NewV4()
	job = &core.Job{
		ID:          id,
		Name:        profile.Channel.String(),
		Description: comm.SetHandlerCommString(host, session),
		JobCtrl:     make(chan bool),
		Ticker:      time.NewTicker(3600 * time.Second), // By default we don't care: one tick per hour
		Profile:     profile.ToProtobuf(),
	}

	// If the job is running on a session, we assign the specifics
	if session != nil {
		job.SessionID = session.HostUUID
		job.SessionName = session.Name
		job.SessionUsername = session.Username
	}

	// Monitor for kill signal in the background.
	// Will perform all cleanups and job deregistering.
	go job.HandleCleanup()

	return
}

// InitHandlerJob - After your C2 channel stack has been correctly setup and successfully started, this function
// takes care of initializing the handler job order, and pushing it through the Sliver server's event system.
func InitHandlerJob(job *core.Job, ln net.Listener) {

	session := core.Sessions.GetByUUID(job.SessionID)  // this might be nil...
	job.Order = core.Jobs.NextSessionJobCount(session) // because this deals with a potentially nil session

	// Register the cleanup function for this listener:
	// This is will be the first listener to be closed,
	// and then any underlying listeners/interfaces will be closed
	job.RegisterCleanup(func() error {
		if ln != nil {
			return ln.Close()
		}
		return nil
	})

	// Finally add the job so everyone notices it.
	core.Jobs.Add(job)
}

// StartPersistentSessionJobs - Start jobs that were set for a given session (UUID+name)
func StartPersistentSessionJobs(session *core.Session) (err error) {

	// Get the jobs only for the very session we want, because
	// several builds might run on the same host.
	jobs, err := db.JobsBySession(session.Name, session.Username, session.HostUUID)
	if err != nil {
		return err
	}

	// Sort jobs by their order, not their IDs
	var keys []int
	for _, job := range jobs {
		keys = append(keys, job.Order)
	}
	sort.Ints(keys)

	var ordered []*models.Job
	for _, k := range keys {
		for _, job := range jobs {
			if job.Order == k {
				ordered = append(ordered, job)
			}
		}
	}

	// Add a logger with no client ID
	logger := log.ClientLogger("", "handler")

	// Start each job in the correct order
	for _, persisted := range ordered {

		logger.Infof("Restarting persistent session job %s", core.GetShortID(persisted.ID.String()))

		// Get the current transport for this session: some of them, like beacons
		// or those that are expressely comm disabled, can run persistent jobs
		transport, err := db.C2ProfileByID(session.TransportID)
		if err != nil {
			return err
		}
		// We get the comm.Net interface for the session: if nil,
		// pass 0 and return the server interfaces functions
		var net comm.Net
		if transport.CommDisabled {
			return errors.New("Current transport is Comm-disabled")
		} else if transport.Type == sliverpb.C2Type_Beacon {
			return errors.New("Current C2 is a beacon, does not support persistent jobs for now")
		} else {
			net, err = comm.ActiveNetwork(session.ID)
			if err != nil {
				return err
			}
		}

		// Init profile security details: load certificates and keys if any, or default.
		// As well, if there are nothing in it, it will just load the default
		err = SetupHandlerSecurity(persisted.Profile, persisted.Profile.Hostname)
		if err != nil {
			return err
		}

		// A job object that will be used after the listener dialer is started,
		// for saving it into the database or server config if the job is persistent
		job, listener := NewHandlerJob(persisted.Profile, session)

		// Dispatch the profile to either the root Dialer functions or Listener ones.
		// The actual implementation of the C2 handlers are in there, or possibly in
		// functions still down the way.
		switch persisted.Profile.Direction {

		// Dialers
		case sliverpb.C2Direction_Bind:
			err = Dial(logger, persisted.Profile, net, session)
			if err != nil {
				return err
			}

		// Listeners
		case sliverpb.C2Direction_Reverse:
			// This is supposed to return us a
			// job but we don't need to save it again
			err := Listen(logger, persisted.Profile, net, job, listener)
			if err != nil {
				return err
			}

			// If we are here, it means the C2 stack has successfully started
			// (within what can be guaranteed excluding goroutine-based stuff).
			// Assign an order value to this job and register it to the server job & event system.
			InitHandlerJob(job, listener)
		}

	}

	return
}

// StartPersistentServerJobs - Start persistent jobs that will run on the server's interfaces.
func StartPersistentServerJobs(cfg *configs.ServerConfig) error {
	if cfg.Jobs == nil {
		return nil
	}

	// Add a logger with no client ID
	logger := log.ClientLogger("", "handler")

	for _, persisted := range cfg.Jobs {

		logger.Infof("Restarting persistent server job %s", core.GetShortID(persisted.ID))

		// Any low level management stuff before anything.
		profile := models.C2ProfileFromProtobuf(persisted.Profile)

		// We get the comm.Net interface for the session: if nil,
		// pass 0 and return the server interfaces functions
		net, err := comm.ActiveNetwork(0)
		if err != nil {
			return err
		}

		// Init profile security details: load certificates and keys if any, or default.
		// NOTE: No hostname is passed as argument, as this is a just a listener started,
		// and that if any Cert/Key data is in the profile, this call below will not touch anything.
		//
		// As well, if there are nothing in it, it will just load the default
		err = SetupHandlerSecurity(profile, profile.Hostname)
		if err != nil {
			return err
		}

		// A job object that will be used after the listener dialer is started,
		// for saving it into the database or server config if the job is persistent
		job, listener := NewHandlerJob(profile, nil)

		// Dispatch the profile to either the root Dialer functions or Listener ones.
		// The actual implementation of the C2 handlers are in there, or possibly in
		// functions still down the way.
		switch profile.Direction {

		// Dialers
		case sliverpb.C2Direction_Bind:
			err = Dial(logger, profile, net, nil)
			if err != nil {
				return err
			}

		// Listeners
		case sliverpb.C2Direction_Reverse:
			// This is supposed to return us a
			// job but we don't need to save it again
			err = Listen(logger, profile, net, job, listener)
			if err != nil {
				return err
			}
			// If we are here, it means the C2 stack has successfully started
			// (within what can be guaranteed excluding goroutine-based stuff).
			// Assign an order value to this job and register it to the server job & event system.
			InitHandlerJob(job, listener)
		}
	}
	return nil
}

// checkInterface verifies if an IP address
// is attached to an existing network interface
func checkInterface(a string) bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, i := range interfaces {
		addresses, err := i.Addrs()
		if err != nil {
			return false
		}
		for _, netAddr := range addresses {
			addr, err := net.ResolveTCPAddr("tcp", netAddr.String())
			if err != nil {
				return false
			}
			if addr.IP.String() == a {
				return true
			}
		}
	}
	return false
}

// Fuck'in Go - https://stackoverflow.com/questions/30815244/golang-https-server-passing-certfile-and-kyefile-in-terms-of-byte-array
// basically the same as server.ListenAndServerTLS() but we can pass in byte slices instead of file paths
// func listenAndServeTLS(srv *http.Server, certPEMBlock, keyPEMBlock []byte) error {
//         addr := srv.Addr
//         if addr == "" {
//                 addr = ":https"
//         }
//         config := &tls.Config{}
//         if srv.TLSConfig != nil {
//                 *config = *srv.TLSConfig
//         }
//         // if config.NextProtos == nil {
//         //         config.NextProtos = []string{"http/1.1"}
//         // }
//
//         var err error
//         config.Certificates = make([]tls.Certificate, 1)
//         config.Certificates[0], err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
//         if err != nil {
//                 return err
//         }
//
//         ln, err := net.Listen("tcp", addr)
//         if err != nil {
//                 return err
//         }
//
//         tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
//         return srv.Serve(tlsListener)
// }
//
// // tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// // connections. It's used by ListenAndServe and ListenAndServeTLS so
// // dead TCP connections (e.g. closing laptop mid-download) eventually
// // go away.
// type tcpKeepAliveListener struct {
//         *net.TCPListener
// }
//
// func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
//         tc, err := ln.AcceptTCP()
//         if err != nil {
//                 return
//         }
//         tc.SetKeepAlive(true)
//         tc.SetKeepAlivePeriod(3 * time.Minute)
//         return tc, nil
// }
