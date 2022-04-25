package cbmcrypt

import (
	"fmt"

	"golang.org/x/crypto/chacha20"
)

type CBMDeriver struct {
	deriveConst []byte
}

func NewCBMDeriver(drvConst []byte) *CBMDeriver {
	res := new(CBMDeriver)
	if drvConst == nil {
		res.deriveConst = []byte{0x43, 0x42, 0x4d, 0x43, 0x52, 0x59, 0x50, 0x54} // cbmcrypt in PETSCII
	} else {
		res.deriveConst = drvConst
	}

	return res
}

func (c *CBMDeriver) DeriveCBMCryptKey(keyData []byte, keyId []byte) (derivedKey []byte, checkValue []byte, err error) {
	derivationNonce := make([]byte, len(c.deriveConst))
	copy(derivationNonce, c.deriveConst)
	derivationNonce = append(derivationNonce, keyId...)
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

func (c *CBMDeriver) CustomizeCheckValue(checkValue []byte, noncePrefix []byte) []byte {
	res := make([]byte, len(checkValue))
	copy(res, checkValue)
	res[0] ^= noncePrefix[0]
	res[1] ^= noncePrefix[1]

	return res
}
