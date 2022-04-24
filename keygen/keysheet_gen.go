package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"

	"crypto/rand"

	"golang.org/x/crypto/chacha20"
)

var SeedLength uint16 = 16

type RenderFunc func(k *KeySheet) error

type PetsciiHelper struct {
	petsciiTable [64]byte
	convTable    map[byte]byte
}

func NewPetsciiHelper() *PetsciiHelper {
	res := new(PetsciiHelper)
	res.petsciiTable = [64]byte{
		// '0'-'9'
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
		// 'a'-''z
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
		0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
		0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
		// 'A'-'Z'
		0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca,
		0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4,
		0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
		// '+','/'
		0x2b, 0x2f,
	}

	res.convTable = map[byte]byte{
		0x30: '0', 0x31: '1', 0x32: '2', 0x33: '3', 0x34: '4', 0x35: '5', 0x36: '6', 0x37: '7', 0x38: '8', 0x39: '9',
		0x41: 'a', 0x42: 'b', 0x43: 'c', 0x44: 'd', 0x45: 'e', 0x46: 'f', 0x47: 'g', 0x48: 'h', 0x49: 'i', 0x4a: 'j',
		0x4b: 'k', 0x4c: 'l', 0x4d: 'm', 0x4e: 'n', 0x4f: 'o', 0x50: 'p', 0x51: 'q', 0x52: 'r', 0x53: 's', 0x54: 't',
		0x55: 'u', 0x56: 'v', 0x57: 'w', 0x58: 'x', 0x59: 'y', 0x5a: 'z',
		0xc1: 'A', 0xc2: 'B', 0xc3: 'C', 0xc4: 'D', 0xc5: 'E', 0xc6: 'F', 0xc7: 'G', 0xc8: 'H', 0xc9: 'I', 0xca: 'J',
		0xcb: 'K', 0xcc: 'L', 0xcd: 'M', 0xce: 'N', 0xcf: 'O', 0xd0: 'P', 0xd1: 'Q', 0xd2: 'R', 0xd3: 'S', 0xd4: 'T',
		0xd5: 'U', 0xd6: 'V', 0xd7: 'W', 0xd8: 'X', 0xd9: 'Y', 0xda: 'Z',
		0x2b: '+', 0x2f: '/',
	}

	return res
}

func (p *PetsciiHelper) IndexToPetscii(val byte) byte {
	val = val & 0x3F

	return p.petsciiTable[val]
}

func (p *PetsciiHelper) PetsciiToChar(val byte) byte {
	return p.convTable[val]
}

func (p *PetsciiHelper) PetsciiSliceToString(data []byte) string {
	res := []byte{}
	for _, j := range data {
		res = append(res, p.PetsciiToChar(j))
	}

	return string(res)
}

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

func (k *KeySheet) AddEntry(e *KeySheetEntry) {
	k.Entries = append(k.Entries, e)
}

type KeySheetCollection struct {
	Title          string
	NumberOfCopies uint16
	NumberOfDays   uint16
	SeedLen        uint16
	Copies         []*KeySheet
	deriver        *CBMDeriver
	petscii        *PetsciiHelper
}

func NewKeySheetCollection(title string, numOfCopies uint16, numOfDays uint16) *KeySheetCollection {
	res := new(KeySheetCollection)
	res.Title = title
	res.NumberOfCopies = numOfCopies
	res.NumberOfDays = numOfDays
	res.Copies = []*KeySheet{}
	res.SeedLen = SeedLength
	res.deriver = NewCBMDeriver(nil)
	res.petscii = NewPetsciiHelper()

	return res
}

func (k *KeySheetCollection) AddCopy(s *KeySheet) {
	k.Copies = append(k.Copies, s)
}

func (k *KeySheetCollection) Generate() error {
	// Initialize each copy
	var count uint16

	for count = 0; count < k.NumberOfCopies; count++ {
		k.AddCopy(NewKeySheet(k.Title, count))
	}

	// generate key Ids for all days for which the sheet is valid
	keyIDs := map[uint16]bool{}

	for len(keyIDs) != int(k.NumberOfDays) {
		temp := []byte{0, 0}
		_, err := rand.Read(temp)
		if err != nil {
			return fmt.Errorf("unable to generate keyids: %v", err)
		}

		keyIDs[uint16(temp[0])+256*uint16(temp[1])] = true
	}

	// Add an entry for each key id to each copy
	for v := range keyIDs {
		// generate key for the day
		seedRaw := make([]byte, k.SeedLen)
		_, err := rand.Read(seedRaw)
		if err != nil {
			return fmt.Errorf("unable to generate key seed: %v", err)
		}

		// turn it into PETSCII
		for i := range seedRaw {
			seedRaw[i] = k.petscii.IndexToPetscii(seedRaw[i])
		}

		// Perform key derivation
		keyIDAsBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(keyIDAsBytes, v)

		_, checkValue, err := k.deriver.DeriveCBMCryptKey(seedRaw, keyIDAsBytes)
		if err != nil {
			return fmt.Errorf("unable to derive actual key: %v", err)
		}

		// Generate a nonce prefix for each copy
		noncePrefixes := map[uint16]bool{}
		for len(noncePrefixes) != int(k.NumberOfCopies) {
			temp := []byte{0, 0}
			_, err := rand.Read(temp)
			if err != nil {
				return fmt.Errorf("unable to generate nonce prefix: %v", err)
			}

			noncePrefixes[uint16(temp[0])+256*uint16(temp[1])] = true
		}

		// Add an entry for the current day to each copy using one of the nonce prefixes
		var copyId uint16 = 0
		for j := range noncePrefixes {
			noncePrefixAsBytes := []byte{0, 0}
			binary.LittleEndian.PutUint16(noncePrefixAsBytes, j)
			customCheckValue := k.deriver.CustomizeCheckValue(checkValue, noncePrefixAsBytes)
			newSheetEntry := NewKeySheetEntry(seedRaw, keyIDAsBytes, noncePrefixAsBytes, customCheckValue)
			k.Copies[copyId].AddEntry(newSheetEntry)

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

func (k *KeySheetCollection) DiagnosticRenderer(sheet *KeySheet) error {
	fmt.Println(sheet.Title)
	fmt.Printf("Copy Nr.: %d\n", sheet.CopyId+1)
	for _, j := range sheet.Entries {
		fmt.Print(k.petscii.PetsciiSliceToString(j.KeySeed))
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
}

func main() {
	const defaultRendererName = "default"
	titlePtr := flag.String("title", "Default", "Title of the key sheet")
	numCopiesPtr := flag.Uint("copies", 2, "Number of copies, i.e. number of participants")
	numDaysPtr := flag.Uint("num-keys", 31, "Number of keys on sheet")
	keyLenPtr := flag.Uint("key-len", uint(SeedLength), "Number of characters in key")
	rendererPtr := flag.String("renderer", defaultRendererName, "How to render the key sheet")

	flag.Parse()

	if *numCopiesPtr < 1 {
		fmt.Println("There has to be at least one copy")
		return
	}

	if *numDaysPtr < 1 {
		fmt.Println("There has to be at least one key on the sheet")
		return
	}

	if *keyLenPtr < 15 {
		fmt.Println("There have to be at least 15 characters in a key")
		return
	}

	if *keyLenPtr > 32 {
		fmt.Println("There must not be more than 32 characters in a key")
		return
	}

	keySheets := NewKeySheetCollection(*titlePtr, uint16(*numCopiesPtr), uint16(*numDaysPtr))
	keySheets.SeedLen = uint16(*keyLenPtr)

	rendererMap := map[string]RenderFunc{}
	rendererMap[defaultRendererName] = keySheets.DiagnosticRenderer

	renderFunc, ok := rendererMap[*rendererPtr]
	if !ok {
		fmt.Println("Renderer unknown")
		return
	}

	err := keySheets.Generate()
	if err != nil {
		fmt.Println(err)
		return
	}

	err = keySheets.RenderAll(renderFunc)
	if err != nil {
		fmt.Println(err)
		return
	}
}
