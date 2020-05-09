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
	"bytes"
	"crypto/rand"
	"testing"

	implantEncoders "github.com/bishopfox/sliver/sliver/encoders"
)

func randomData() []byte {
	buf := make([]byte, 128)
	rand.Read(buf)
	return buf
}

func TestEnglish(t *testing.T) {
	sample := randomData()
	english := new(English)
	encoded := english.Encode(sample)
	data, err := english.Decode(encoded)
	if err != nil {
		t.Error("Failed to encode sample data into english")
		return
	}
	if !bytes.Equal(sample, data) {
		t.Errorf("sample does not match returned\n%#v != %#v", sample, data)
	}
}

func TestHex(t *testing.T) {
	sample := randomData()

	// Server-side
	x := new(Hex)
	output := x.Encode(sample)
	data, err := x.Decode(output)
	if err != nil {
		t.Errorf("hex decode returned an error %v", err)
	}
	if !bytes.Equal(sample, data) {
		t.Errorf("sample does not match returned\n%#v != %#v", sample, data)
	}

	// Implant-side
	implantHex := new(implantEncoders.Hex)
	output2 := implantHex.Encode(sample)
	data2, err := implantHex.Decode(output2)
	if err != nil {
		t.Errorf("implant hex decode returned an error %v", err)
	}
	if !bytes.Equal(sample, data2) {
		t.Errorf("sample does not match returned\n%#v != %#v", sample, data)
	}

	// Interoperability
	if bytes.Compare(output, output2) != 0 {
		t.Errorf("impant encoder does not match server-side encoder %s", err)
	}

	data3, err := implantHex.Decode(output)
	if err != nil {
		t.Errorf("implant hex decode could not decode server data %v", err)
	}
	if !bytes.Equal(sample, data3) {
		t.Errorf("implant decoded sample of server data does not match returned\n%#v != %#v", sample, data)
	}
}

func TestBase64(t *testing.T) {
	sample := randomData()
	b64 := new(Base64)
	output := b64.Encode(sample)
	data, err := b64.Decode(output)
	if err != nil {
		t.Errorf("b64 decode returned an error %v", err)
	}
	if !bytes.Equal(sample, data) {
		t.Logf("sample = %#v", sample)
		t.Logf("output = %#v", output)
		t.Logf("  data = %#v", data)
		t.Errorf("sample does not match returned\n%#v != %#v", sample, data)
	}

	implantBase64 := new(implantEncoders.Base64)
	data2, err := implantBase64.Decode(output)
	if err != nil {
		t.Errorf("implant b64 decode returned an error %v", err)
	}
	if !bytes.Equal(sample, data2) {
		t.Logf("sample  = %#v", sample)
		t.Logf("output  = %#v", output)
		t.Logf("  data2 = %#v", data2)
		t.Errorf("sample does not match returned\n%#v != %#v", sample, data)
	}
	output2 := implantBase64.Encode(sample)
	if !bytes.Equal(output, output2) {
		t.Logf("sample  = %#v", sample)
		t.Logf("output1 = %#v", output)
		t.Logf("output2 = %#v", output2)
		t.Errorf("server and implant outputs differ\n%#v != %#v", sample, data)
	}
}
