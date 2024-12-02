// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package engine

import "github.com/btcsuite/btcd/txscript"

// scriptError creates an Error given a set of arguments.
func scriptError(c txscript.ErrorCode, desc string) txscript.Error {
	return txscript.Error{ErrorCode: c, Description: desc}
}
