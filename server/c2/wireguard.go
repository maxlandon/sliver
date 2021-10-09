package c2

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

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
	"bufio"
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"github.com/bishopfox/sliver/server/certs"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/bishopfox/sliver/server/log"
	"github.com/bishopfox/sliver/server/netstack"
)

var (
	wgLog = log.NamedLogger("c2", "wg")
	tunIP = "100.64.0.1" // Don't let user configure this for now
)

var (
	wgipsLog = log.RootLogger.WithFields(logrus.Fields{
		"pkg":    "generate",
		"stream": "wgips",
	})
)

// StartWireGuardDevInterface - Create, configure and start:
// - An inet.af network stack.
// - An interface device through which key-exchange & session connections will pass.
// This function also starts monitoring new device interface peers in the background.
func StartWireGuardDevInterface(profile *models.C2Profile, job *core.Job) (tNet *netstack.Net, err error) {

	wgLog.Infof("Starting Wireguard listener on port: %d", profile.Port)

	tun, tNet, err := netstack.CreateNetTUN(
		[]net.IP{net.ParseIP(tunIP)},
		[]net.IP{net.ParseIP("127.0.0.1")}, // We don't use DNS in the WG listener. Yet.
		1420,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateNetTUN failed: %v", err)
	}

	// Get existing server wg keys. TODO: change if profile specifies certain keys
	privateKey, _, err := certs.GetWGServerKeys()

	if err != nil {
		isPeer := false
		privateKey, _, err = certs.GenerateWGKeys(isPeer, "")
		if err != nil {
			return nil, err
		}
	}

	// This is currently set to silence all logs from the wg device
	// Set this to device.LogLevelVerbose when debugging for verbose logs
	// We should probably set this to LogLevelError and figure out how to
	// redirect the logs from stdout
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "[c2/wg] "))

	// Populate and setup the device configuration
	wgConf := bytes.NewBuffer(nil)
	fmt.Fprintf(wgConf, "private_key=%s\n", privateKey)
	fmt.Fprintf(wgConf, "listen_port=%d\n", profile.Port)

	peers, err := certs.GetWGPeers()
	if err != nil && err != certs.ErrWGPeerDoesNotExist {
		return nil, err
	}

	for k, v := range peers {
		fmt.Fprintf(wgConf, "public_key=%s\n", k)
		fmt.Fprintf(wgConf, "allowed_ip=%s/32\n", v)
	}

	// Load the device config
	if err := dev.IpcSetOperation(bufio.NewReader(wgConf)); err != nil {
		return nil, err
	}

	// Start the device interface
	err = dev.Up()
	if err != nil {
		return nil, fmt.Errorf("Could not set up the device: %v", err)
	}

	// Register the cleanup function for closing the device interface
	job.RegisterCleanup(func() error {
		return dev.Down()
	})

	// Setup and start the goroutine handling new peer connections.
	job.Ticker.Reset(5 * time.Second) // Refresh the dev monitoring every 5 seconds
	go serveDeviceInterfacePeers(dev, wgConf, job.JobCtrl, job.Ticker)

	return
}

// serveDeviceInterfacePeers - Monitor the Wireguard device interface for new peer connections in the background.
func serveDeviceInterfacePeers(dev *device.Device, config *bytes.Buffer, done chan bool, ticker *time.Ticker) {
	oldNumPeers := 0
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			currentPeers, err := certs.GetWGPeers()
			if err != nil {
				jobLog.Errorf("Failed to get current Wireguard Peers %s", err)
				continue
			}

			if len(currentPeers) > oldNumPeers {
				jobLog.Infof("New WG peers. Updating Wireguard config")

				oldNumPeers = len(currentPeers)

				jobLog.Infof("Old WG config for peers: %s", config.String())
				for k, v := range currentPeers {
					fmt.Fprintf(config, "public_key=%s\n", k)
					fmt.Fprintf(config, "allowed_ip=%s/32\n", v)
				}

				jobLog.Infof("New WG config for peers: %s", config.String())

				if err := dev.IpcSetOperation(bufio.NewReader(config)); err != nil {
					jobLog.Errorf("Failed to update Wireguard Config %s", err)
					continue
				}
				jobLog.Infof("Successfully updated Wireguard config")
			}
		}
	}
}

// ListenWireGuard - Start a TCP listener that handles incoming WireGuard implant session requests.
// The listener returned is compliant with the generic RPC setup/usage mechanism, because it yields net.Conns
func ListenWireGuard(profile *models.C2Profile, job *core.Job, tNet *netstack.Net) (ln net.Listener, err error) {

	// Start listening for key exchange requests
	keyExchangeListener, err := tNet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(tunIP), Port: int(profile.KeyExchangePort)})
	if err != nil {
		return nil, fmt.Errorf("Failed to setup up key exchange listener: %v", err)
	}
	wgLog.Printf("Successfully setup up wg key exchange listener")
	go serveKeyExchangeListener(keyExchangeListener)

	// Register cleanup for key exchange listener
	job.RegisterCleanup(func() error {
		if keyExchangeListener != nil {
			return keyExchangeListener.Close()
		}
		return nil
	})

	// Start a listener waiting for session connections requests and return it
	ln, err = tNet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(tunIP), Port: int(profile.ControlPort)})
	if err != nil {
		return nil, fmt.Errorf("Failed to start TCP listener: %v", err)
	}

	wgLog.Printf("Successfully setup up wg sliver listener")

	return
}

// serveKeyExchangeListener - accept connections to key exchange socket
func serveKeyExchangeListener(ln net.Listener) {
	wgLog.Printf("Polling for connections to key exchange listener")
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errType, ok := err.(*net.OpError); ok && errType.Op == "accept" {
				wgLog.Errorf("Accept failed: %v", err)
				break
			}
			wgLog.Errorf("Accept failed: %v", err)
			continue
		}
		wgLog.Infof("Accepted connection to wg key exchange listener: %s", conn.RemoteAddr())
		go handleKeyExchangeConnection(conn)
	}
}

// handleKeyExchangeConnection - Retrieve current wg server pub key.
// Generate new implant wg keys. Generate new unique IP for implant.
// Write all retrieved data to socket connection.
func handleKeyExchangeConnection(conn net.Conn) {
	wgLog.Infof("Handling connection to key exchange listener")

	defer conn.Close()
	ip, err := GenerateUniqueIP()
	if err != nil {
		wgLog.Errorf("Failed to generate unique IP: %s", err)
	}

	implantPrivKey, _, err := certs.ImplantGenerateWGKeys(ip.String())
	if err != nil {
		wgLog.Errorf("Failed to generate new wg keys: %s", err)
	}

	_, serverPubKey, err := certs.GetWGServerKeys()
	if err != nil {
		wgLog.Errorf("Failed to retrieve existing wg server keys: %s", err)
	} else {
		wgLog.Infof("Successfully generated new wg keys")
		message := implantPrivKey + "|" + serverPubKey + "|" + string(ip)
		wgLog.Debugf("Sending new wg keys and IP: %s", message)
		conn.Write([]byte(message))
	}
}

// GenerateUniqueIP generates and returns an available IP which can then
// be assigned to a Wireguard interface
func GenerateUniqueIP() (net.IP, error) {
	dbWireguardIPs, err := db.WGPeerIPs()
	if err != nil {
		// wgipsLog.Errorf("Failed to retrieve list of WG Peers IPs with error: %s", err)
		return nil, err
	}

	// Use the 100.64.0.1/16 range for TUN ips.
	// This range chosen due to Tailscale also using it (Cut down to /16 instead of /10)
	// https://tailscale.com/kb/1015/100.x-addresses
	addressPool, err := hosts("100.64.0.1/16")
	if err != nil {
		// wgipsLog.Errorf("Failed to generate host address pool for WG Peers IPs %s", err)
		return nil, err
	}

	for _, address := range addressPool {
		for _, ip := range dbWireguardIPs {
			if ip == address {
				addressPool = remove(addressPool, []string{ip})
				break
			}
		}
	}

	return net.ParseIP(addressPool[0]), nil
}

// Reserve use of 100.64.0.{0|1} addresses
var reservedAddresses = []string{"100.64.0.0", "100.64.0.1"}

func hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	ips = remove(ips, reservedAddresses)
	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func remove(stringSlice []string, remove []string) []string {
	var result []string
	for _, v := range stringSlice {
		shouldAppend := true
		for _, value := range remove {
			if v == value {
				shouldAppend = false
			}
		}
		if shouldAppend {
			result = append(result, v)
		}
	}
	return result
}
