// Package cbmcrypt implements the key derivation algorithm used by CBMCrypt
package cbmcrypt

import (
	"fmt"

	"golang.org/x/crypto/chacha20"
)

// CBMDeriver binds the data together that is needed to perform a CBMCrypt key derivation
type CBMDeriver struct {
	deriveConst []byte
}

// NewCBMDeriver creates and initializes a new CBMDeriver struct
func NewCBMDeriver(drvConst []byte) *CBMDeriver {
	res := new(CBMDeriver)
	if drvConst == nil {
		res.deriveConst = []byte{0x43, 0x42, 0x4d, 0x43, 0x52, 0x59, 0x50, 0x54} // cbmcrypt in PETSCII
	} else {
		res.deriveConst = drvConst
	}

	return res
}

// DeriveCBMCryptKey performs a key derivation using the specified key seed and also returns a check value that depends
// on the key seed and the key ID.
func (c *CBMDeriver) DeriveCBMCryptKey(keyData []byte, keyID []byte) (derivedKey []byte, checkValue []byte, err error) {
	derivationNonce := make([]byte, len(c.deriveConst))
	copy(derivationNonce, c.deriveConst)
	derivationNonce = append(derivationNonce, keyID...)
	for len(derivationNonce) < 12 {
		derivationNonce = append(derivationNonce, 0)
	}

	if len(keyData) > 32 {
		return nil, nil, fmt.Errorf("key seed is too large")
	}

	if len(keyData) < 15 {
		return nil, nil, fmt.Errorf("key seed is too small")
	}

	if len(keyData) < 32 {
		numBytesToPad := 32 - len(keyData)
		for i := 0; i < numBytesToPad; i++ {
			keyData = append(keyData, 0)
		}
	}

	cip, err := chacha20.NewUnauthenticatedCipher(keyData, derivationNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("key derivation failed: %v", err)
	}

	cip.SetCounter(1)

	derivedKey = make([]byte, 32)
	cip.XORKeyStream(derivedKey, derivedKey)

	checkValue = make([]byte, 3)
	cip.XORKeyStream(checkValue, checkValue)

	return derivedKey, checkValue, nil
}

// CustomizeCheckValue modfies the check value returned by DeriveCBMCryptKey in such a way that it is also
// dependent of the nonce prefix. Therefore all necessary components influence the check value that has to
// be entered by the user.
func (c *CBMDeriver) CustomizeCheckValue(checkValue []byte, noncePrefix []byte) []byte {
	res := make([]byte, len(checkValue))
	copy(res, checkValue)
	res[0] ^= noncePrefix[0]
	res[1] ^= noncePrefix[1]

	return res
}
