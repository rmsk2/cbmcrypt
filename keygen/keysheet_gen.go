package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"crypto/rand"

	"golang.org/x/crypto/chacha20"
)

var SeedLength uint16 = 16

type RenderFunc func(k *KeySheet) error

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

type KeySheetEntry struct {
	KeySeed     []byte
	KeyID       []byte
	NoncePrefix []byte
	CheckValue  []byte
}

func NewKeySheetEntry(seed []byte, keyID []byte, noncePrefix []byte, checkValue []byte) *KeySheetEntry {
	res := new(KeySheetEntry)
	res.KeySeed = seed
	res.KeyID = keyID
	res.NoncePrefix = noncePrefix
	res.CheckValue = checkValue

	return res
}

type KeySheet struct {
	Title   string
	CopyId  uint16
	Entries []*KeySheetEntry
}

func NewKeySheet(title string, copyId uint16) *KeySheet {
	res := new(KeySheet)
	res.Title = title
	res.CopyId = copyId
	res.Entries = []*KeySheetEntry{}

	return res
}

// For each day there is a key seed and and  key id
// For each copy on any given day there is a nonce prefix and check value for each entry
// All key ids on a sheet have to be different
// All key ids for any given day have to equal on each sheet
// All nonce prefixes for any given day have to be different for all copies
//
// There has to be a unique key id for each day. This key id is equal on all copies
// There has to be a unique nonce prefix for all corresponding entries on all copies
type KeySheetCollection struct {
	Title          string
	NumberOfCopies uint16
	NumberOfDays   uint16
	SeedLen        uint16
	Copies         []*KeySheet
	deriver        *CBMDeriver
}

func NewKeySheetCollection(title string, numOfCopies uint16, numOfDays uint16) *KeySheetCollection {
	res := new(KeySheetCollection)
	res.Title = title
	res.NumberOfCopies = numOfCopies
	res.NumberOfDays = numOfDays
	res.Copies = []*KeySheet{}
	res.SeedLen = SeedLength
	res.deriver = NewCBMDeriver(nil)

	return res
}

func toPetscii(val byte) byte {
	val = val & 0x3F
	petsciiTable := [64]byte{
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
		0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
		0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
		0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca,
		0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4,
		0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
		0x2b, 0x2f,
	}

	return petsciiTable[val]
}

func fromPetscii(val byte) byte {
	convTable := map[byte]byte{
		0x30: '0',
		0x31: '1',
		0x32: '2',
		0x33: '3',
		0x34: '4',
		0x35: '5',
		0x36: '6',
		0x37: '7',
		0x38: '8',
		0x39: '9',
		0x41: 'a',
		0x42: 'b',
		0x43: 'c',
		0x44: 'd',
		0x45: 'e',
		0x46: 'f',
		0x47: 'g',
		0x48: 'h',
		0x49: 'i',
		0x4a: 'j',
		0x4b: 'k',
		0x4c: 'l',
		0x4d: 'm',
		0x4e: 'n',
		0x4f: 'o',
		0x50: 'p',
		0x51: 'q',
		0x52: 'r',
		0x53: 's',
		0x54: 't',
		0x55: 'u',
		0x56: 'v',
		0x57: 'w',
		0x58: 'x',
		0x59: 'y',
		0x5a: 'z',
		0xc1: 'A',
		0xc2: 'B',
		0xc3: 'C',
		0xc4: 'D',
		0xc5: 'E',
		0xc6: 'F',
		0xc7: 'G',
		0xc8: 'H',
		0xc9: 'I',
		0xca: 'J',
		0xcb: 'K',
		0xcc: 'L',
		0xcd: 'M',
		0xce: 'N',
		0xcf: 'O',
		0xd0: 'P',
		0xd1: 'Q',
		0xd2: 'R',
		0xd3: 'S',
		0xd4: 'T',
		0xd5: 'U',
		0xd6: 'V',
		0xd7: 'W',
		0xd8: 'X',
		0xd9: 'Y',
		0xda: 'Z',
		0x2b: '+',
		0x2f: '/',
	}

	return convTable[val]
}

func sliceToPescii(data []byte) string {
	res := []byte{}
	for _, j := range data {
		res = append(res, fromPetscii(j))
	}

	return string(res)
}

func (k *KeySheetCollection) Generate() error {
	keyIDs := map[uint16]bool{}

	// generate key Ids
	for len(keyIDs) != int(k.NumberOfDays) {
		temp := []byte{0, 0}
		_, err := rand.Read(temp)
		if err != nil {
			return fmt.Errorf("unable to generate keyids: %v", err)
		}

		keyIDs[uint16(temp[0])+256*uint16(temp[1])] = true
	}

	var i uint16

	// Initialize each copy
	for i = 0; i < k.NumberOfCopies; i++ {
		k.Copies = append(k.Copies, NewKeySheet(k.Title, i))
	}

	// Add an entry for each key id to each copy
	for v := range keyIDs {
		// generate key for the day
		seedRaw := make([]byte, SeedLength)
		_, err := rand.Read(seedRaw)
		if err != nil {
			return fmt.Errorf("unable to generate key seed: %v", err)
		}

		// turn it into PETSCII
		for i := range seedRaw {
			seedRaw[i] = toPetscii(seedRaw[i])
		}

		// Perform key derivation
		keyIDAsBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(keyIDAsBytes, v)

		_, checkValue, err := k.deriver.DeriveCBMCryptKey(seedRaw, keyIDAsBytes)
		if err != nil {
			return fmt.Errorf("unable to derive actual key: %v", err)
		}

		// Generate nonce prefixes for the day
		noncePrefixes := map[uint16]bool{}
		for len(noncePrefixes) != int(k.NumberOfCopies) {
			temp := []byte{0, 0}
			_, err := rand.Read(temp)
			if err != nil {
				return fmt.Errorf("unable to generate nonce prefix: %v", err)
			}

			noncePrefixes[uint16(temp[0])+256*uint16(temp[1])] = true
		}

		// Add an entry to each copy for the current day
		var copyId uint16 = 0
		for j := range noncePrefixes {
			noncePrefixAsBytes := []byte{0, 0}
			binary.LittleEndian.PutUint16(noncePrefixAsBytes, j)
			customCheckValue := k.deriver.CustomizeCheckValue(checkValue, noncePrefixAsBytes)
			newSheetEntry := NewKeySheetEntry(seedRaw, keyIDAsBytes, noncePrefixAsBytes, customCheckValue)
			k.Copies[copyId].Entries = append(k.Copies[copyId].Entries, newSheetEntry)

			copyId++
		}
	}

	return nil
}

func (k *KeySheetCollection) RenderAll(renderer RenderFunc) error {
	for _, j := range k.Copies {
		err := renderer(j)
		if err != nil {
			return fmt.Errorf("unable to render copy %d: %v", j.CopyId, err)
		}
	}
	return nil
}

func main() {
	keySheets := NewKeySheetCollection("Schlüsselkreis Test", 2, 31)
	err := keySheets.Generate()
	if err != nil {
		fmt.Println(err)
		return
	}

	err = keySheets.RenderAll(func(sheet *KeySheet) error {
		for _, j := range sheet.Entries {
			fmt.Print(sliceToPescii(j.KeySeed))
			fmt.Print(" ")
			fmt.Print(hex.EncodeToString(j.KeyID))
			fmt.Print(" ")
			fmt.Print(hex.EncodeToString(j.NoncePrefix))
			fmt.Print(" ")
			fmt.Print(hex.EncodeToString(j.CheckValue))
			fmt.Println()
		}

		fmt.Println()

		return nil
	})
	if err != nil {
		fmt.Println(err)
		return
	}
}
