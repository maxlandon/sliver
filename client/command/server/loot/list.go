package loot

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
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/maxlandon/readline"
	"gopkg.in/AlecAivazis/survey.v1"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// List - Display the server's loot store with various displays
type List struct {
	// Positional struct {
	//         Filter string `description:"types of loot to include in display. Can be more than one." required:"1"`
	// } `positional-args:"true" required:"true"`
	Options struct {
		Filter string `long:"filter" short:"f" description:"types of loot to include in display. Can be more than one."`
	} `group:"display options"`
}

// Execute - Display the server's loot store with various displays
func (l *List) Execute(args []string) (err error) {

	filter := l.Options.Filter
	var allLoot *clientpb.AllLoot
	if filter == "" {
		allLoot, err = transport.RPC.LootAll(context.Background(), &commonpb.Empty{})
		if err != nil {
			return log.Errorf("Failed to fetch loot: %s", err)
		}
	} else {
		lootType, err := lootTypeFromHumanStr(filter)
		if err != nil {
			return log.Errorf("Invalid loot type see --help")
		}
		allLoot, err = transport.RPC.LootAllOf(context.Background(), &clientpb.Loot{Type: lootType})
		if err != nil {
			return log.Errorf("Failed to fetch loot: %s", err)
		}
	}
	if filter == "" {
		PrintAllLootTable(allLoot)
	} else {
		lootType, _ := lootTypeFromHumanStr(filter)
		switch lootType {
		case clientpb.LootType_LOOT_FILE:
			PrintAllFileLootTable(allLoot)
		case clientpb.LootType_LOOT_CREDENTIAL:
			PrintAllCredentialLootTable(allLoot)
		}
	}
	return
}

// PrintLootFile - Display the contents of a piece of loot
func PrintLootFile(loot *clientpb.Loot) {
	if loot.File == nil {
		return
	}
	fmt.Println()

	if loot.File.Name != "" {
		fmt.Printf("%sFile Name:%s %s\n\n", readline.YELLOW, readline.YELLOW, loot.File.Name)
	}
	if loot.File.Data != nil && 0 < len(loot.File.Data) {
		if loot.FileType == clientpb.FileType_TEXT || isText(loot.File.Data) {
			fmt.Printf("%s", string(loot.File.Data))
		} else {
			fmt.Printf("<%d bytes of binary data>\n", len(loot.File.Data))
		}
	} else {
		fmt.Printf("No file data\n")
	}
}

// PrintLootCredential - Display all credentials in a list-like setting, not table
func PrintLootCredential(loot *clientpb.Loot) {

	switch loot.CredentialType {
	case clientpb.CredentialType_USER_PASSWORD:
		if loot.Credential != nil {
			fmt.Printf("%s    User:%s %s\n", readline.YELLOW, readline.RESET, loot.Credential.User)
			fmt.Printf("%sPassword:%s %s\n", readline.YELLOW, readline.RESET, loot.Credential.Password)
		}
		if loot.File != nil {
			PrintLootFile(loot)
		}
	case clientpb.CredentialType_API_KEY:
		if loot.Credential != nil {
			fmt.Printf("%sAPI Key:%s %s\n", readline.YELLOW, readline.RESET, loot.Credential.APIKey)
		}
		if loot.File != nil {
			PrintLootFile(loot)
		}
	case clientpb.CredentialType_FILE:
		if loot.File != nil {
			PrintLootFile(loot)
		}
	default:
		fmt.Printf("%v\n", loot.Credential) // Well, let's give it our best
	}
}

// PrintAllLootTable - Displays a table of all files loot
func PrintAllLootTable(allLoot *clientpb.AllLoot) {
	if allLoot == nil || len(allLoot.Loot) == 0 {
		log.Infof("No loot in the server's store")
		return
	}

	table := util.NewTable("")
	headers := []string{"Type", "Name", "UUID"}
	headLen := []int{10, 10, 10}
	table.SetColumns(headers, headLen)

	for _, loot := range allLoot.Loot {
		table.AppendRow([]string{
			lootTypeToStr(loot.Type),
			loot.Name,
			loot.LootID})
	}
	table.Output()
}

// PrintAllFileLootTable - Displays a table of all files loot
func PrintAllFileLootTable(allLoot *clientpb.AllLoot) {
	if allLoot == nil || len(allLoot.Loot) == 0 {
		log.Infof("No loot in the server's store")
		return
	}

	table := util.NewTable("")
	headers := []string{"Type", "Name", "File Name", "Size", "UUID"}
	headLen := []int{0, 0, 0, 0, 0}
	table.SetColumns(headers, headLen)

	for _, loot := range allLoot.Loot {
		if loot.Type != clientpb.LootType_LOOT_FILE {
			continue
		}
		size := 0
		name := ""
		if loot.File != nil {
			name = loot.File.Name
			size = len(loot.File.Data)
		}
		var shortID string
		if len(loot.LootID) < 8 {
			shortID = loot.LootID[:len(loot.LootID)]
		} else {
			shortID = loot.LootID[:8]
		}
		table.AppendRow([]string{
			fileTypeToStr(loot.FileType),
			loot.Name,
			name,
			strconv.Itoa(size),
			shortID})
	}
	table.Output()
}

// PrintAllCredentialLootTable - Displays a table of all credential loot
func PrintAllCredentialLootTable(allLoot *clientpb.AllLoot) {
	if allLoot == nil || len(allLoot.Loot) == 0 {
		log.Infof("No loot in the server's store")
		return
	}

	table := util.NewTable("")
	headers := []string{"Type", "Name", "User", "Password", "API Key", "File Name", "UUID"}
	headLen := []int{0, 0, 0, 0, 0, 0, 0}
	table.SetColumns(headers, headLen)

	for _, loot := range allLoot.Loot {
		if loot.Type != clientpb.LootType_LOOT_CREDENTIAL {
			continue
		}
		fileName := ""
		if loot.File != nil {
			fileName = loot.File.Name
		}
		user := ""
		password := ""
		apiKey := ""
		if loot.Credential != nil {
			user = loot.Credential.User
			password = loot.Credential.Password
			apiKey = loot.Credential.APIKey
		}
		var shortID string
		if len(loot.LootID) < 8 {
			shortID = loot.LootID[:len(loot.LootID)]
		} else {
			shortID = loot.LootID[:8]
		}
		table.AppendRow([]string{
			credentialTypeToString(loot.CredentialType),
			loot.Name,
			user,
			password,
			apiKey,
			fileName,
			shortID})
	}
	table.Output()
}

func lootTypeToStr(value clientpb.LootType) string {
	switch value {
	case clientpb.LootType_LOOT_FILE:
		return "File"
	case clientpb.LootType_LOOT_CREDENTIAL:
		return "Credential"
	default:
		return ""
	}
}

func credentialTypeToString(value clientpb.CredentialType) string {
	switch value {
	case clientpb.CredentialType_API_KEY:
		return "API Key"
	case clientpb.CredentialType_USER_PASSWORD:
		return "User/Password"
	case clientpb.CredentialType_FILE:
		return "File"
	default:
		return ""
	}
}

func fileTypeToStr(value clientpb.FileType) string {
	switch value {
	case clientpb.FileType_BINARY:
		return "Binary"
	case clientpb.FileType_TEXT:
		return "Text"
	default:
		return ""
	}
}

func lootFileTypeFromHumanStr(value string) (clientpb.FileType, error) {
	switch strings.ToLower(value) {

	case "b":
		fallthrough
	case "bin":
		fallthrough
	case "binary":
		return clientpb.FileType_BINARY, nil

	case "t":
		fallthrough
	case "utf-8":
		fallthrough
	case "utf8":
		fallthrough
	case "txt":
		fallthrough
	case "text":
		return clientpb.FileType_TEXT, nil

	default:
		return -1, ErrInvalidFileType
	}
}

func lootTypeFromHumanStr(value string) (clientpb.LootType, error) {
	switch strings.ToLower(value) {

	case "c":
		fallthrough
	case "cred":
		fallthrough
	case "creds":
		fallthrough
	case "credentials":
		fallthrough
	case "credential":
		return clientpb.LootType_LOOT_CREDENTIAL, nil

	case "f":
		fallthrough
	case "files":
		fallthrough
	case "file":
		return clientpb.LootType_LOOT_FILE, nil

	default:
		return -1, ErrInvalidLootType
	}
}

// Taken from: https://cs.opensource.google/go/x/tools/+/refs/tags/v0.1.4:godoc/util/util.go;l=69

// textExt[x] is true if the extension x indicates a text file, and false otherwise.
var textExt = map[string]bool{
	".css": false, // Ignore as text
	".js":  false, // Ignore as text
	".svg": false, // Ignore as text
}

// isTextFile reports whether the file has a known extension indicating
// a text file, or if a significant chunk of the specified file looks like
// correct UTF-8; that is, if it is likely that the file contains human-
// readable text.
func isTextFile(filePath string) bool {
	// if the extension is known, use it for decision making
	if isText, found := textExt[path.Ext(filePath)]; found {
		return isText
	}

	// the extension is not known; read an initial chunk
	// of the file and check if it looks like text
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	var buf [1024]byte
	n, err := f.Read(buf[0:])
	if err != nil {
		return false
	}

	return isText(buf[0:n])
}

// isText reports whether a significant prefix of s looks like correct UTF-8;
// that is, if it is likely that s is human-readable text.
func isText(sample []byte) bool {
	const max = 1024 // at least utf8.UTFMax
	if len(sample) > max {
		sample = sample[0:max]
	}
	for i, c := range string(sample) {
		if i+utf8.UTFMax > len(sample) {
			// last char may be incomplete - ignore
			break
		}
		if c == 0xFFFD || c < ' ' && c != '\n' && c != '\t' && c != '\f' {
			// decoding error or control character - not a text file
			return false
		}
	}
	return true
}

// Any loot with a "File" can be saved to disk
func saveLootToDisk(saveTo string, loot *clientpb.Loot) (string, error) {
	if loot.File == nil {
		return "", errors.New("Loot does not contain a file")
	}

	fi, err := os.Stat(saveTo)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err == nil && fi.IsDir() {
		saveTo = path.Join(saveTo, path.Base(loot.File.Name))
	}
	if _, err := os.Stat(saveTo); err == nil {
		overwrite := false
		prompt := &survey.Confirm{Message: "Overwrite local file?"}
		survey.AskOne(prompt, &overwrite, nil)
		if !overwrite {
			return "", nil
		}
	}
	err = ioutil.WriteFile(saveTo, loot.File.Data, 0600)
	return saveTo, err
}
