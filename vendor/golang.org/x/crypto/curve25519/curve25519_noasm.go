// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

<<<<<<< HEAD
// +build !amd64 gccgo appengine purego
=======
//go:build !amd64 || !gc || purego
// +build !amd64 !gc purego
>>>>>>> BishopFox/master

package curve25519

func scalarMult(out, in, base *[32]byte) {
	scalarMultGeneric(out, in, base)
}
