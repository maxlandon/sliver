package console

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
	"fmt"
	"path"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/protobuf/rpcpb"

	"github.com/TheZoraiz/ascii-image-converter/aic_package"
)

func printSliverBanner(rpc rpcpb.SliverRPCClient) {
	assets.SetupInstinct()
	pathToInstinct := path.Join(assets.GetArtDir(), "instinct.jpg")

	flags := aic_package.DefaultFlags()
	flags.Colored = true
	flags.Braille = true
	flags.Dither = true
	flags.Height = 35

	// This MUST be set to true for environments where a terminal isn't available (such as web servers)
	// However, for this, one of flags.Width, flags.Height or flags.Dimensions must be set.
	flags.NoTermSizeComparison = true

	starring, err := aic_package.Convert(pathToInstinct, flags)
	if err != nil {
		printLogo(rpc)
	} else {
		fmt.Printf("%v\n", starring)
	}

	// Then print version information
	printVersionInfo(rpc)
}
