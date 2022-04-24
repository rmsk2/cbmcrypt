package main

import (
	"bytes"
	"testing"
)

func TestDerivation(t *testing.T) {
	keyId := []byte{0x11, 0x22}
	noncePrefix := []byte{0x00, 0x01}
	seedRaw := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 10, 11, 12, 13, 14, 15}
	petscii := NewPetsciiHelper()
	deriver := NewCBMDeriver(nil)

	seed := []byte{}
	for _, j := range seedRaw {
		seed = append(seed, petscii.IndexToPetscii(j))
	}

	_, checkValue, err := deriver.DeriveCBMCryptKey(seed, keyId)
	if err != nil {
		t.Fatal(err)
	}

	refVal := []byte{0x93, 0x87, 0x0c}
	modifiedCheckValue := deriver.CustomizeCheckValue(checkValue, noncePrefix)
	if !bytes.Equal(refVal, modifiedCheckValue) {
		t.Fatal("Unexpected check value")
	}
}
