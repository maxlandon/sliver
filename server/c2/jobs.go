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
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	consts "github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/comm"
	"github.com/bishopfox/sliver/server/configs"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/bishopfox/sliver/server/log"
	"github.com/gofrs/uuid"
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
	core.CleanupSessionTransports = CleanupSessionTransports
}

// StartDNSListenerJob - Start a DNS listener as a job
func StartDNSListenerJob(bindIface string, lport uint16, domains []string, canaries bool) (*core.Job, error) {
	server := StartDNSListener(bindIface, lport, domains, canaries)
	description := fmt.Sprintf("%s (canaries %v)", strings.Join(domains, " "), canaries)
	job := &core.Job{
		// ID:          core.NextJobID(),
		Name:        "dns",
		Description: description,
		// Protocol:    "udp",
		// Port:        lport,
		JobCtrl: make(chan bool),
		// Domains:     domains,
	}

	go func() {
		<-job.JobCtrl
		jobLog.Infof("Stopping DNS listener (%d) ...", job.ID)
		server.Shutdown()
		core.Jobs.Remove(job)
		core.EventBroker.Publish(core.Event{
			Job:       job,
			EventType: consts.JobStoppedEvent,
		})
	}()

	core.Jobs.Add(job)

	// There is no way to call DNS' ListenAndServe() without blocking
	// but we also need to check the error in the case the server
	// fails to start at all, so we setup all the Job mechanics
	// then kick off the server and if it fails we kill the job
	// ourselves.
	go func() {
		err := server.ListenAndServe()
		if err != nil {
			jobLog.Errorf("DNS listener error %v", err)
			job.JobCtrl <- true
		}
	}()

	return job, nil
}

// StartHTTPListenerJob - Start a HTTP listener as a job
func StartHTTPListenerJob(conf *HTTPServerConfig) (*core.Job, error) {
	server, err := StartHTTPSListener(conf)
	if err != nil {
		return nil, err
	}
	name := "http"
	if conf.Secure {
		name = "https"
	}

	job := &core.Job{
		// ID:          core.NextJobID(),
		Name:        name,
		Description: fmt.Sprintf("%s for domain %s", name, conf.Domain),
		// Protocol:    "tcp",
		// Port:        uint16(conf.LPort),
		JobCtrl: make(chan bool),
		// Domains:     []string{conf.Domain},
	}
	core.Jobs.Add(job)

	cleanup := func(err error) {
		server.Cleanup()
		core.Jobs.Remove(job)
		core.EventBroker.Publish(core.Event{
			Job:       job,
			EventType: consts.JobStoppedEvent,
			Err:       err,
		})
	}
	once := &sync.Once{}

	go func() {
		var err error
		if server.ServerConf.Secure {
			if server.ServerConf.ACME {
				err = server.HTTPServer.ListenAndServeTLS("", "") // ACME manager pulls the certs under the hood
			} else {
				err = listenAndServeTLS(server.HTTPServer, conf.Cert, conf.Key)
			}
		} else {
			err = server.HTTPServer.ListenAndServe()
		}
		if err != nil {
			jobLog.Errorf("%s listener error %v", name, err)
			once.Do(func() { cleanup(err) })
			job.JobCtrl <- true // Cleanup other goroutine
		}
	}()

	go func() {
		<-job.JobCtrl
		once.Do(func() { cleanup(nil) })
	}()

	return job, nil
}

// StartTCPStagerListenerJob - Start a TCP staging payload listener
func StartTCPStagerListenerJob(host string, port uint16, shellcode []byte) (*core.Job, error) {
	ln, err := StartTCPListener(host, port, shellcode)
	if err != nil {
		return nil, err // If we fail to bind don't setup the Job
	}

	job := &core.Job{
		// ID:          core.NextJobID(),
		Name:        "TCP",
		Description: "Raw TCP listener (stager only)",
		// Protocol:    "tcp",
		// Port:        port,
		JobCtrl: make(chan bool),
	}

	go func() {
		<-job.JobCtrl
		jobLog.Infof("Stopping TCP listener (%d) ...", job.ID)
		ln.Close() // Kills listener GoRoutines in startMutualTLSListener() but NOT connections

		core.Jobs.Remove(job)

		core.EventBroker.Publish(core.Event{
			Job:       job,
			EventType: consts.JobStoppedEvent,
		})
	}()

	core.Jobs.Add(job)

	return job, nil
}

// StartHTTPStagerListenerJob - Start an HTTP(S) stager payload listener
func StartHTTPStagerListenerJob(conf *HTTPServerConfig, data []byte) (*core.Job, error) {
	server, err := StartHTTPSListener(conf)
	if err != nil {
		return nil, err
	}
	name := "http"
	if conf.Secure {
		name = "https"
	}
	server.SliverStage = data
	job := &core.Job{
		// ID:          core.NextJobID(),
		Name:        name,
		Description: fmt.Sprintf("Stager handler %s for domain %s", name, conf.Domain),
		// Protocol:    "tcp",
		// Port:        uint16(conf.LPort),
		JobCtrl: make(chan bool),
	}
	core.Jobs.Add(job)

	cleanup := func(err error) {
		server.Cleanup()
		core.Jobs.Remove(job)
		core.EventBroker.Publish(core.Event{
			Job:       job,
			EventType: consts.JobStoppedEvent,
			Err:       err,
		})
	}
	once := &sync.Once{}

	go func() {
		var err error
		if server.ServerConf.Secure {
			if server.ServerConf.ACME {
				err = server.HTTPServer.ListenAndServeTLS("", "") // ACME manager pulls the certs under the hood
			} else {
				err = listenAndServeTLS(server.HTTPServer, conf.Cert, conf.Key)
			}
		} else {
			err = server.HTTPServer.ListenAndServe()
		}
		if err != nil {
			jobLog.Errorf("%s listener error %v", name, err)
			once.Do(func() { cleanup(err) })
			job.JobCtrl <- true // Cleanup other goroutine
		}
	}()

	go func() {
		<-job.JobCtrl
		once.Do(func() { cleanup(nil) })
	}()

	return job, nil
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

	// Start each job in the correct order
	for _, job := range ordered {

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
		err = SetupHandlerSecurity(job.Profile, job.Profile.Hostname)
		if err != nil {
			return err
		}

		// Dispatch the profile to either the root Dialer functions or Listener ones.
		// The actual implementation of the C2 handlers are in there, or possibly in
		// functions still down the way.
		switch job.Profile.Direction {

		// Dialers
		case sliverpb.C2Direction_Bind:
			err = Dial(job.Profile, net, session)
			if err != nil {
				return err
			}

		// Listeners
		case sliverpb.C2Direction_Reverse:
			// This is supposed to return us a
			// job but we don't need to save it again
			_, err := Listen(job.Profile, net, session)
			if err != nil {
				return err
			}
		}
	}

	return
}

// StartPersistentServerJobs - Start persistent jobs that will run on the server's interfaces.
func StartPersistentServerJobs(cfg *configs.ServerConfig) error {
	if cfg.Jobs == nil {
		return nil
	}

	for _, job := range cfg.Jobs {
		// Any low level management stuff before anything.
		profile := models.C2ProfileFromProtobuf(job.Profile)

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

		// Dispatch the profile to either the root Dialer functions or Listener ones.
		// The actual implementation of the C2 handlers are in there, or possibly in
		// functions still down the way.
		switch profile.Direction {

		// Dialers
		case sliverpb.C2Direction_Bind:
			err = Dial(profile, net, nil)
			if err != nil {
				return err
			}

		// Listeners
		case sliverpb.C2Direction_Reverse:
			// This is supposed to return us a
			// job but we don't need to save it again
			_, err := Listen(profile, net, nil)
			if err != nil {
				return err
			}
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
func listenAndServeTLS(srv *http.Server, certPEMBlock, keyPEMBlock []byte) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}
	config := &tls.Config{}
	if srv.TLSConfig != nil {
		*config = *srv.TLSConfig
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
	return srv.Serve(tlsListener)
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
