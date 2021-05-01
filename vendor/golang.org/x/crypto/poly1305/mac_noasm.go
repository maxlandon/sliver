// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

<<<<<<< HEAD
// +build !amd64,!ppc64le,!s390x gccgo purego
=======
//go:build (!amd64 && !ppc64le && !s390x) || !gc || purego
// +build !amd64,!ppc64le,!s390x !gc purego
>>>>>>> BishopFox/master

package poly1305

type mac struct{ macGeneric }
