package db

/*
	Sliver Implant Framework
	Copyright (C) 2020  Bishop Fox

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
	----------------------------------------------------------------------

    IMPORTANT: These should be read-only functions and cannot rely on any
               packages outside of /server/db/models

*/

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/bishopfox/sliver/server/db/models"
	"github.com/gofrs/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	// ErrRecordNotFound - Record not found error
	ErrRecordNotFound = gorm.ErrRecordNotFound
)

// GetShortID - Get a shorter 8 bits ID that is better to work with in commands and completions
func GetShortID(ID string) (short string) {
	if len(ID) < 8 {
		short = ID
	} else {
		short = ID[:8]
	}
	return
}

// ImplantConfigByID - Fetch implant build by name
func ImplantConfigByID(id string) (*models.ImplantConfig, error) {
	config := models.ImplantConfig{}
	err := Session().Where(&models.ImplantConfig{
		ID: uuid.FromStringOrNil(id),
	}).First(&config).Error
	if err != nil {
		return nil, err
	}
	return &config, err
}

// ImplantConfigByECCPublicKeyDigest - Fetch implant build by it's ecc public key
func ImplantConfigByECCPublicKeyDigest(publicKeyDigest [32]byte) (*models.ImplantConfig, error) {
	config := models.ImplantConfig{}
	err := Session().Where(&models.ImplantConfig{
		ECCPublicKeyDigest: hex.EncodeToString(publicKeyDigest[:]),
	}).First(&config).Error
	if err != nil {
		return nil, err
	}
	return &config, err
}

// JobsBySession - Return all the persistent jobs that are saved for a given session NAME & host UUID
// Does not check name for now, as we don't have sessions in DB.
func JobsBySession(sessionName, sessionUserName, hostUuid string) (jobs []*models.Job, err error) {

	err = Session().Where(&models.Job{
		HostID:          uuid.FromStringOrNil(hostUuid),
		SessionName:     sessionName,
		SessionUsername: sessionUserName,
	}).
		Preload("Profile").
		Find(&jobs).Error
	if err != nil {
		return jobs, err
	}
	for _, job := range jobs {
		err = loadC2ProfileForJob(job)
		if err != nil {
			return jobs, err
		}
	}
	return
}

// JobByID - Retrieve a Job by its UUID. These are jobs that
// are running on a session and marked persistent.
func JobByID(jobID string) (*models.Job, error) {
	job := &models.Job{}
	err := Session().Where(&models.Job{}).
		Preload("Profile").
		Find(&job).Error
	if err != nil {
		return nil, err
	}
	err = loadC2ProfileForJob(job)
	if err != nil {
		return job, err
	}
	return job, nil
}

// SessionJobSave - Save a persistent job running on a session
func SessionJobSave(job *models.Job) error {
	dbSession := Session()
	result := dbSession.Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(&job)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// ImplantBuilds - Return all implant builds
func ImplantBuilds() ([]*models.ImplantBuild, error) {
	builds := []*models.ImplantBuild{}
	err := Session().Where(&models.ImplantBuild{}).
		Preload("ImplantConfig").
		Preload("Transports").
		Find(&builds).Error
	if err != nil {
		return nil, err
	}
	// Load the C2 both in the build and in the config
	for _, build := range builds {
		err = loadTransportsForBuild(build)
		if err != nil {
			return nil, err
		}
	}
	for _, build := range builds {
		err = loadTransportsForConfig(&build.ImplantConfig)
		if err != nil {
			return nil, err
		}
	}
	return builds, err
}

// ImplantBuildByName - Fetch implant build by name
func ImplantBuildByName(name string) (*models.ImplantBuild, error) {
	build := models.ImplantBuild{}
	err := Session().Where(&models.ImplantBuild{
		Name: name,
	}).Preload("ImplantConfig").
		Preload("Transports").
		First(&build).Error
	if err != nil {
		return nil, err
	}
	err = loadTransportsForBuild(&build)
	if err != nil {
		return nil, err
	}
	err = loadTransportsForConfig(&build.ImplantConfig)
	if err != nil {
		return nil, err
	}

	return &build, err
}

// ImplantBuildNames - Fetch a list of all build names
func ImplantBuildNames() ([]string, error) {
	builds := []*models.ImplantBuild{}
	err := Session().Where(&models.ImplantBuild{}).Find(&builds).Error
	if err != nil {
		return []string{}, err
	}
	names := []string{}
	for _, build := range builds {
		names = append(names, build.Name)
	}
	return names, nil
}

// ImplantProfiles - Fetch a map of name<->profiles current in the database
func ImplantProfiles() ([]*models.ImplantProfile, error) {
	profiles := []*models.ImplantProfile{}
	err := Session().Where(&models.ImplantProfile{}).Preload("ImplantConfig").Find(&profiles).Error
	if err != nil {
		return nil, err
	}

	for _, profile := range profiles {
		err = loadTransportsForConfig(profile.ImplantConfig)
		if err != nil {
			return nil, err
		}
	}
	return profiles, nil
}

// ImplantProfileByName - Fetch implant build by name
func ImplantProfileByName(name string) (*models.ImplantProfile, error) {
	profile := models.ImplantProfile{}
	err := Session().Where(&models.ImplantProfile{
		Name: name,
	}).Preload("ImplantConfig").First(&profile).Error
	if err != nil {
		return nil, err
	}

	err = loadTransportsForConfig(profile.ImplantConfig)
	if err != nil {
		return nil, err
	}

	return &profile, err
}

// loadTransportsForConfig - Load the C2Profiles that have been compiled into a build.
func loadTransportsForConfig(config *models.ImplantConfig) error {
	transports := []*models.Transport{}
	err := Session().Where(&models.Transport{
		ImplantBuildID: config.ImplantBuildID,
	}).Find(&transports).Error
	if err != nil {
		return err
	}
	config.Transports = transports
	return nil
}

// loadTransportsForBuild - Load the C2Profiles that have been compiled into a build.
func loadTransportsForBuild(build *models.ImplantBuild) error {
	transports := []*models.Transport{}
	err := Session().Where(&models.Transport{
		ImplantBuildID: build.ID,
	}).Find(&transports).Error
	if err != nil {
		return err
	}
	build.Transports = transports
	return nil
}

// loadC2ProfilesForJob - Load the C2 Profile used to spawn a job an a session
func loadC2ProfileForJob(job *models.Job) error {
	c2 := &models.Malleable{}
	err := Session().Where(&models.Malleable{
		JobID: job.ID,
	}).Find(&c2).Error
	if err != nil {
		return err
	}
	job.Profile = c2
	return nil
}

// loadC2ProfileForTransport - Load the C2 Profile used to run a transport on a Session
func loadC2ProfileForTransport(transport *models.Transport) error {
	c2 := &models.Malleable{}
	err := Session().Where(&models.Malleable{
		ID: transport.ProfileID,
	}).Find(&c2).Error
	if err != nil {
		return err
	}
	transport.Profile = c2
	return nil
}

// C2ProfileByHostPortNameSession - Fetch a Malleable C2 profile by host, port and name, generally for confirmation purposes
func C2ProfileByHostPortNameSession(host string, port uint32, name, sessionID string) (profile *models.Malleable, err error) {
	err = Session().Where(&models.Malleable{
		ContextSessionID: uuid.FromStringOrNil(sessionID),
		Hostname:         host,
		Port:             port,
		Name:             name,
		Persistent:       false, // always return non persistent profiles, because those are only meant for listeners
	}).First(&profile).Error
	return
}

// C2ProfileByID - Fetch a Malleable C2 profile by ID
func C2ProfileByID(ID string) (c2 *models.Malleable, err error) {
	c2 = &models.Malleable{}
	err = Session().Where(&models.Malleable{
		ID: uuid.FromStringOrNil(ID),
	}).Find(&c2).Error
	return c2, nil
}

// C2ProfilesByContextSessionID - Get all C2 Profiles that have been created within a given session context.
func C2ProfilesByContextSessionID(sessionID string) (profiles []*models.Malleable, err error) {
	err = Session().Where(&models.Malleable{
		ContextSessionID: uuid.FromStringOrNil(sessionID),
		Persistent:       false, // always return non persistent profiles, because those are only meant for listeners
	}).Find(&profiles).Error
	return
}

// C2ProfileByShortID - Fetch a Malleable C2 profile by a short ID used by commands/completions
func C2ProfileByShortID(ID string) (c2 *models.Malleable, err error) {

	profiles := []*models.Malleable{}
	err = Session().Find(&profiles).Error
	if err != nil {
		return nil, err
	}

	for _, profile := range profiles {
		if GetShortID(profile.ID.String()) == ID {
			return profile, nil
		}
	}

	return nil, fmt.Errorf("Could not find Profile with short ID %s", ID)
}

// TransportByID - Get a session transport by its ID
func TransportByID(ID string) (transport *models.Transport, err error) {
	err = Session().Where(&models.Transport{
		ID: uuid.FromStringOrNil(ID),
	}).Find(&transport).Error
	if err != nil {
		return
	}

	err = loadC2ProfileForTransport(transport)
	return
}

// TransportByShortID - Fetch a session transport by a short ID used by commands/completions
func TransportByShortID(ID string) (transport *models.Transport, err error) {

	transports := []*models.Transport{}
	err = Session().Find(&transports).Error
	if err != nil {
		return nil, err
	}

	for _, transport := range transports {
		if GetShortID(transport.ID.String()) == ID {
			return transport, nil
		}
	}

	return nil, fmt.Errorf("Could not find Transport with short ID %s", ID)
}

// TransportsForBuild - Loads all the transports compiled into an implant build, not fetching those set at runtime.
func TransportsForBuild(name string) (transports []*models.Transport, err error) {

	// Compiled transports
	build, err := ImplantBuildByName(name)
	if err != nil {
		return transports, err
	}
	var compiled []*models.Transport
	for _, buildTransport := range build.Transports {
		found := false
		for _, transport := range transports {
			if transport.ID == buildTransport.ID {
				found = true
				break
			}
		}
		if !found {
			compiled = append(compiled, buildTransport)
		}
	}

	// Add those compiled transports to the list
	transports = append(transports, compiled...)

	// Load profiles for all
	for _, transport := range transports {
		err = loadC2ProfileForTransport(transport)
		if err != nil {
			return nil, err
		}
	}

	return
}

// TransportsBySession - Loads all the transports currently available to (loaded on) an implant.
// These will be either those compiled in, or a partially/fully different set if they have been changed at runtime.
func TransportsBySession(ID string) (transports []*models.Transport, err error) {

	// Runtime/active transports
	err = Session().Where(&models.Transport{
		SessionID: uuid.FromStringOrNil(ID),
	}).Find(&transports).Error

	// Load profiles for all
	for _, transport := range transports {
		err = loadC2ProfileForTransport(transport)
		if err != nil {
			return nil, err
		}
	}

	return
}

// ImplantProfileNames - Fetch a list of all build names
func ImplantProfileNames() ([]string, error) {
	profiles := []*models.ImplantProfile{}
	err := Session().Where(&models.ImplantProfile{}).Find(&profiles).Error
	if err != nil {
		return []string{}, err
	}
	names := []string{}
	for _, build := range profiles {
		names = append(names, build.Name)
	}
	return names, nil
}

// ProfileByName - Fetch a single profile from the database
func ProfileByName(name string) (*models.ImplantProfile, error) {
	dbProfile := &models.ImplantProfile{}
	err := Session().Where(&models.ImplantProfile{Name: name}).Find(&dbProfile).Error
	return dbProfile, err
}

// ListCanaries - List of all embedded canaries
func ListCanaries() ([]*models.DNSCanary, error) {
	canaries := []*models.DNSCanary{}
	err := Session().Where(&models.DNSCanary{}).Find(&canaries).Error
	return canaries, err
}

// CanaryByDomain - Check if a canary exists
func CanaryByDomain(domain string) (*models.DNSCanary, error) {
	dbSession := Session()
	canary := models.DNSCanary{}
	err := dbSession.Where(&models.DNSCanary{Domain: domain}).First(&canary).Error
	return &canary, err
}

// WebsiteByName - Get website by name
func WebsiteByName(name string) (*models.Website, error) {
	website := models.Website{}
	err := Session().Where(&models.Website{Name: name}).First(&website).Error
	if err != nil {
		return nil, err
	}
	return &website, nil
}

// WGPeerIPs - Fetch a list of ips for all wireguard peers
func WGPeerIPs() ([]string, error) {
	wgPeers := []*models.WGPeer{}
	err := Session().Where(&models.WGPeer{}).Find(&wgPeers).Error
	if err != nil {
		return nil, err
	}
	ips := []string{}
	for _, peer := range wgPeers {
		ips = append(ips, peer.TunIP)
	}
	return ips, nil
}

// ListHosts - List of all hosts in the database
func ListHosts() ([]*models.Host, error) {
	hosts := []*models.Host{}
	err := Session().Where(
		&models.Host{},
	).Preload("IOCs").Preload("ExtensionData").Find(&hosts).Error
	return hosts, err
}

// HostByHostID - Get host by the session's reported HostUUID
func HostByHostID(id uuid.UUID) (*models.Host, error) {
	host := models.Host{}
	err := Session().Where(&models.Host{ID: id}).First(&host).Error
	if err != nil {
		return nil, err
	}
	return &host, nil
}

// HostByHostUUID - Get host by the session's reported HostUUID
func HostByHostUUID(id string) (*models.Host, error) {
	host := models.Host{}
	err := Session().Where(
		&models.Host{HostUUID: uuid.FromStringOrNil(id)},
	).Preload("IOCs").Preload("ExtensionData").First(&host).Error
	if err != nil {
		return nil, err
	}
	return &host, nil
}

// IOCByID - Select an IOC by ID
func IOCByID(id string) (*models.IOC, error) {
	ioc := &models.IOC{}
	err := Session().Where(
		&models.IOC{ID: uuid.FromStringOrNil(id)},
	).First(ioc).Error
	return ioc, err
}

// BeaconByID - Select a Beacon by ID
func BeaconByID(id string) (*models.Beacon, error) {
	beacon := &models.Beacon{}
	err := Session().Where(
		&models.Beacon{ID: uuid.FromStringOrNil(id)},
	).First(beacon).Error
	return beacon, err
}

// BeaconTasksByBeaconID - Get all tasks for a specific beacon
// by default will not fetch the request/response columns since
// these could be arbitrarily large.
func BeaconTasksByBeaconID(beaconID string) ([]*models.BeaconTask, error) {
	beaconTasks := []*models.BeaconTask{}
	id := uuid.FromStringOrNil(beaconID)
	err := Session().Select([]string{
		"ID", "EnvelopeID", "BeaconID", "CreatedAt", "State", "SentAt", "CompletedAt",
		"Description",
	}).Where(&models.BeaconTask{BeaconID: id}).Find(&beaconTasks).Error
	return beaconTasks, err
}

// BeaconTaskByID - Select a specific BeaconTask by ID, this
// will fetch the full request/response
func BeaconTaskByID(taskID string) (*models.BeaconTask, error) {
	task := &models.BeaconTask{}
	err := Session().Where(
		&models.BeaconTask{ID: uuid.FromStringOrNil(taskID)},
	).First(task).Error
	return task, err
}

// ListBeacons - Select a Beacon by ID
func ListBeacons() ([]*models.Beacon, error) {
	beacons := []*models.Beacon{}
	err := Session().Where(&models.Beacon{}).Find(&beacons).Error
	return beacons, err
}

// PendingBeaconTasksByBeaconID - Select a Beacon by ID
func PendingBeaconTasksByBeaconID(beaconID string) ([]*models.BeaconTask, error) {
	tasks := []*models.BeaconTask{}
	err := Session().Where(
		&models.BeaconTask{
			BeaconID: uuid.FromStringOrNil(beaconID),
			State:    models.PENDING,
		},
	).Find(&tasks).Error
	return tasks, err
}

// UpdateBeaconCheckinByID - Update the beacon's last / next checkin
func UpdateBeaconCheckinByID(beaconID string, next int64) error {
	err := Session().Where(&models.Beacon{
		ID: uuid.FromStringOrNil(beaconID),
	}).Updates(models.Beacon{
		LastCheckin: time.Now(),
		NextCheckin: next,
	}).Error
	return err
}

// BeaconTasksByEnvelopeID - Select a (sent) BeaconTask by its envelope ID
func BeaconTaskByEnvelopeID(beaconID string, envelopeID int64) (*models.BeaconTask, error) {
	task := &models.BeaconTask{}
	err := Session().Where(
		&models.BeaconTask{
			BeaconID:   uuid.FromStringOrNil(beaconID),
			EnvelopeID: envelopeID,
			State:      models.SENT,
		},
	).First(task).Error
	return task, err
}

// CountTasksByBeaconID - Select a (sent) BeaconTask by its envelope ID
func CountTasksByBeaconID(beaconID uuid.UUID) (int64, int64, error) {
	allTasks := int64(0)
	completedTasks := int64(0)
	err := Session().Model(&models.BeaconTask{}).Where(
		&models.BeaconTask{
			BeaconID: beaconID,
		},
	).Count(&allTasks).Error
	if err != nil {
		return 0, 0, err
	}
	err = Session().Model(&models.BeaconTask{}).Where(
		&models.BeaconTask{
			BeaconID: beaconID,
			State:    models.COMPLETED,
		},
	).Count(&completedTasks).Error
	return allTasks, completedTasks, err
}

// OperatorByToken - Select an operator by token value
func OperatorByToken(value string) (*models.Operator, error) {
	operator := &models.Operator{}
	err := Session().Where(&models.Operator{
		Token: value,
	}).First(operator).Error
	return operator, err
}

// OperatorAll - Select all operators from the database
func OperatorAll() ([]*models.Operator, error) {
	operators := []*models.Operator{}
	err := Session().Distinct("Name").Find(&operators).Error
	return operators, err
}
