package registry

/*
	sliver implant framework
	copyright (c) 2019  bishop fox

	this program is free software: you can redistribute it and/or modify
	it under the terms of the gnu general public license as published by
	the free software foundation, either version 3 of the license, or
	(at your option) any later version.

	this program is distributed in the hope that it will be useful,
	but without any warranty; without even the implied warranty of
	merchantability or fitness for a particular purpose.  see the
	gnu general public license for more details.

	you should have received a copy of the gnu general public license
	along with this program.  if not, see <https://www.gnu.org/licenses/>.
*/

type RegistryListSubkeys struct {
	Positional struct {
		Path string `description:"path to the registry directory/key" required:"1-1"`
	} `positional-args:"yes" required:"yes"`
	Options struct {
		Hostname string `description:"optional hostname for registry listing"`
	} `group:"registry list options"`
}

func (rl *RegistryListSubkeys) Execute(args []string) (err error) {
	// session := core.ActiveTarget.Session
	// if session == nil {
	//         return
	// }
	//
	// path := ctx.Args.String("registry-path")
	// hive := ctx.Flags.String("hive")
	// hostname := ctx.Flags.String("hostname")
	//
	// regList, err := con.Rpc.RegistryListSubKeys(context.Background(), &sliverpb.RegistrySubKeyListReq{
	//         Hive:     hive,
	//         Hostname: hostname,
	//         Path:     path,
	//         Request:  con.ActiveTarget.Request(ctx),
	// })
	//
	// if err != nil {
	//         con.PrintErrorf("Error: %s\n", err.Error())
	//         return
	// }
	//
	// if regList.Response != nil && regList.Response.Err != "" {
	//         con.PrintErrorf("Error: %s\n", regList.Response.Err)
	//         return
	// }
	// if len(regList.Subkeys) > 0 {
	//         con.PrintInfof("Sub keys under %s:\\%s:\n", hive, path)
	// }
	// for _, subKey := range regList.Subkeys {
	//         con.Println(subKey)
	// }
	//
	return
}
