package constants

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

// Meta
const (
	// KeepAliveStr - Keep alive constant
	KeepAliveStr = "keepalive"
)

const (
	// LastUpdateCheckFileName - Last update check file name
	LastUpdateCheckFileName = "last_update_check"
)

// Events
const (
	// UpdateStr - "update"
	UpdateStr = "update"
	// VersionStr - "version"
	VersionStr = "version"

	// EventStr - "event"
	EventStr = "event"

	// ServersStr - "server-error"
	ServerErrorStr = "server-error"

	// ConnectedEvent - Sliver Connected
	SessionOpenedEvent = "session-connected"
	// DisconnectedEvent - Sliver disconnected
	SessionClosedEvent = "session-disconnected"
	// UpdateEvent - Sliver updated
	SessionUpdateEvent = "session-updated"

	// JoinedEvent - Player joined the game
	JoinedEvent = "client-joined"
	// LeftEvent - Player left the game
	LeftEvent = "client-left"

	// CanaryEvent - A DNS canary was triggered
	CanaryEvent = "canary"

	// WatchtowerEvent - An implant hash has been identified on a threat intel platform
	WatchtowerEvent = "watchtower"

	// StartedEvent - Job was started
	JobStartedEvent = "job-started"
	// StoppedEvent - Job was stopped
	JobStoppedEvent = "job-stopped"

	// BuildEvent - Fires on change to builds
	BuildEvent = "build"

	// BuildCompletedEvent - Fires when a build completes
	BuildCompletedEvent = "build-completed"

	// ProfileEvent - Fires whenever there's a change to profiles
	ProfileEvent = "profile"

	// WebsiteEvent - Fires whenever there's a change to websites
	WebsiteEvent = "website"

	// LootAdded
	LootAddedEvent = "loot-added"

	// LootRemoved
	LootRemovedEvent = "loot-removed"

	// BeaconRegisteredEvent - First connection from a new beacon
	BeaconRegisteredEvent = "beacon-registered"

	// BeaconTaskResult - Beacon task completed with a result
	BeaconTaskResultEvent = "beacon-taskresult"
)

// Menus
const (
	// ServerMenu - Not interacting with a session
	ServerMenu = "server"
	// SliverMenu - Interacting with a session
	SliverMenu = "sliver"
)

// Commands
const (
	OperatorsStr       = "operators"
	NewOperatorStr     = "new-operator"
	KickOperatorStr    = "kick-operator"
	MultiplayerModeStr = "multiplayer"

	SessionsStr   = "sessions"
	BackgroundStr = "background"
	InfoStr       = "info"
	UseStr        = "use"
	ReconfigStr   = "reconfig"
	PruneStr      = "prune"
	TasksStr      = "tasks"
	GenerateStr   = "generate"
	RegenerateStr = "regenerate"
	CompilerStr   = "info"
	StagerStr     = "stager"
	ProfilesStr   = "profiles"
	BeaconStr     = "beacon"
	BeaconsStr    = "beacons"
	SettingsStr   = "settings"

	// Generic

	// NewStr - "new"
	NewStr    = "new"
	AddStr    = "add"
	StartStr  = "start"
	StopStr   = "stop"
	SetStr    = "set"
	UnsetStr  = "unset"
	SaveStr   = "save"
	ReloadStr = "reload"
	LoadStr   = "load"
	TablesStr = "tables"

	LootStr       = "loot"
	LootLocalStr  = "local"
	LootRemoteStr = "remote"
	LootFetchStr  = "fetch"
	LootCredsStr  = "creds"

	RenameStr = "rename"

	ImplantBuildsStr = "implants"
	CanariesStr      = "canaries"

	JobsStr        = "jobs"
	JobsKillStr    = "kill"
	JobsKillAllStr = "kill-all"
	MtlsStr        = "mtls"
	WGStr          = "wg"
	DnsStr         = "dns"
	HttpStr        = "http"
	HttpsStr       = "https"
	NamedPipeStr   = "named-pipe"
	TCPListenerStr = "tcp-pivot"

	LogStr        = "log"
	ConfigStr     = "settings"
	ConfigSaveStr = "save"
	MsfStr        = "msf"
	MsfInjectStr  = "msf-inject"

	PsStr        = "ps"
	PingStr      = "ping"
	KillStr      = "kill"
	TerminateStr = "terminate"

	GetPIDStr = "getpid"
	GetUIDStr = "getuid"
	GetGIDStr = "getgid"
	WhoamiStr = "whoami"

	ShellStr   = "shell"
	ExecuteStr = "execute"

	LsStr       = "ls"
	RmStr       = "rm"
	MkdirStr    = "mkdir"
	CdStr       = "cd"
	LcdStr      = "lcd"
	PwdStr      = "pwd"
	CatStr      = "cat"
	DownloadStr = "download"
	UploadStr   = "upload"
	IfconfigStr = "ifconfig"
	NetstatStr  = "netstat"

	ProcdumpStr         = "procdump"
	ImpersonateStr      = "impersonate"
	RunAsStr            = "runas"
	ElevateStr          = "elevate"
	GetSystemStr        = "getsystem"
	RevToSelfStr        = "rev2self"
	ExecuteAssemblyStr  = "execute-assembly"
	ExecuteShellcodeStr = "execute-shellcode"
	MigrateStr          = "migrate"
	SideloadStr         = "sideload"
	SpawnDllStr         = "spawndll"
	ExtensionStr        = "extension"
	LoadMacroStr        = "load-macro"
	StageListenerStr    = "stage-listener"

	WebsitesStr       = "websites"
	WebsitesShowStr   = "show"
	RmWebContentStr   = "rm-content"
	AddWebContentStr  = "add-content"
	WebContentTypeStr = "content-type"
	WebUpdateStr      = "update"

	ScreenshotStr         = "screenshot"
	PsExecStr             = "psexec"
	BackdoorStr           = "backdoor"
	MakeTokenStr          = "make-token"
	EnvStr                = "env"
	RegistryStr           = "registry"
	RegistryReadStr       = "read"
	RegistryWriteStr      = "write"
	RegistryListSubStr    = "list-subkeys"
	RegistryListValuesStr = "list-values"
	RegistryCreateKeyStr  = "create"
	PivotsListStr         = "pivots-list"
	WgConfigStr           = "wg-config"
	WgSocksStr            = "wg-socks"
	WgPortFwdStr          = "wg-portfwd"
	MonitorStr            = "monitor"
	SSHStr                = "ssh"
	DLLHijackStr          = "dllhijack"

	PortfwdStr = "portfwd"

	ReactionStr = "reaction"

	HostsStr = "hosts"
	IOCStr   = "ioc"

	LicensesStr = "licenses"

	GetPrivsStr        = "getprivs"
	PreludeOperatorStr = "prelude-operator"
	ConnectStr         = "connect"
)

// Groups
const (
	GenericHelpGroup     = "Generic:"
	SliverHelpGroup      = "Sliver:"
	SliverWinHelpGroup   = "Sliver - Windows:"
	MultiplayerHelpGroup = "Multiplayer:"
	ExtensionHelpGroup   = "Sliver - 3rd Party extensions:"

	// Transport-based
	WireGuardGroup = "WireGuard"
)

// Command categories
const (
	AdminGroup        = "admin"
	CoreServerGroup   = "core (server)"
	BuildsGroup       = "implants"
	TransportsGroup   = "transports"
	SessionsGroup     = "sessions"
	CommGroup         = "comm"
	NetworkToolsGroup = "network tools"

	// Session only
	CoreSessionGroup = "core (session)"
	FilesystemGroup  = "filesystem"
	InfoGroup        = "information"
	ProcGroup        = "process"
	PrivGroup        = "priv"
	ExecuteGroup     = "execution"
	PersistenceGroup = "persistence"
	ExtensionsGroup  = "extensions"
)

// C2 default values
const (
	DefaultMTLSLPort    = 8888
	DefaultWGLPort      = 53
	DefaultWGNPort      = 8888
	DefaultWGKeyExPort  = 1337
	DefaultHTTPLPort    = 80
	DefaultHTTPSLPort   = 443
	DefaultDNSLPort     = 53
	DefaultTCPPivotPort = 9898

	DefaultReconnect = 60
	DefaultPoll      = 1
	DefaultMaxErrors = 1000

	DefaultTimeout = 60
)
