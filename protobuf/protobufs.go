package protobufs

import (
	"embed"
)

var (

	// FS - Embedded FS access to proto files
	// Also includes JSON Schema files in sliverpb,
	// which are used for Malleable profile edition.
	//
	//go:embed commonpb/* sliverpb/* commpb/*
	FS embed.FS
)
