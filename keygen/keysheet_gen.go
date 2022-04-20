package main

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/chacha20"
)

func deriveCBMCryptKey(keyData []byte, keyId []byte) (derivedKey []byte, checkValue []byte, err error) {
	derivationNonce := []byte{0x43, 0x42, 0x4d, 0x43, 0x52, 0x59, 0x50, 0x54} // cbmcrypt in PETSCII
	derivationNonce = append(derivationNonce, keyId...)
	derivationNonce = append(derivationNonce, []byte{0, 0}...)

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

func main() {
	key := []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46}
	noncePrefix := []byte{0x00, 0x01}

	derivedKey, checkValue, err := deriveCBMCryptKey(key, []byte{0x11, 0x22})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(hex.Dump(derivedKey))
	fmt.Println(hex.Dump(checkValue))
	checkValue[0] ^= noncePrefix[0]
	checkValue[1] ^= noncePrefix[1]
	fmt.Println(hex.Dump(checkValue))
}
