package encoders

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
	insecureRand "math/rand"
)

const (
	// EncoderModulus - Nonce % EncoderModulus = EncoderID, and needs to be equal
	//                  to or greater than the number of supported encoders.
	EncoderModulus = 32
)

// Encoder - Can losslessly encode arbitrary binary data to ASCII
type Encoder interface {
	Encode([]byte) []byte
	Decode([]byte) ([]byte, error)
}

// EncoderMap - Maps EncoderIDs to Encoders
var EncoderMap = map[int]Encoder{
	Base64EncoderID:      Base64{},      // 0
	HexEncoderID:         Hex{},         // 1
	EnglishEncoderID:     English{},     // 2
	GzipEncoderID:        Gzip{},        // 3
	GzipEnglishEncoderID: GzipEnglish{}, // 4
	Base64GzipEncoderID:  Base64Gzip{},  // 5
}

// EncoderFromNonce - Convert a nonce into an encoder
func EncoderFromNonce(nonce int) (int, Encoder) {
	encoderID := nonce % EncoderModulus
	if encoder, ok := EncoderMap[encoderID]; ok {
		return encoderID, encoder
	}
	return -1, NoEncoder{}
}

// RandomEncoder - Get a random nonce and encoder
func RandomEncoder() (int, Encoder) {
	encoderID := insecureRand.Intn(len(EncoderMap))
	nonce := (insecureRand.Intn(99999) * EncoderModulus) + encoderID
	return nonce, EncoderMap[encoderID]
}

// NoEncoder - A NOP encoder
type NoEncoder struct{}

// Encode - Don't do anything
func (n NoEncoder) Encode(data []byte) []byte {
	return data
}

// Decode - Don't do anything
func (n NoEncoder) Decode(data []byte) ([]byte, error) {
	return data, nil
}
