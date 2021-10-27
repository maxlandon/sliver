package protobufs

import (
	"embed"
	// Needed by buf tool for tag generation in Malleable profiles Protobuf definitions.
	// _ "github.com/srikrsna/protoc-gen-gotag"
)

var (

	// FS - Embedded FS access to proto files
	//go:embed commonpb/* sliverpb/* commpb/*
	FS embed.FS
)
