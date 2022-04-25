package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"keygen/cbmcrypt"
	"keygen/petscii"

	"crypto/rand"
)

var SeedLength uint16 = 16

type RenderFunc func(k *KeySheet) error

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
	deriver        *cbmcrypt.CBMDeriver
}

func NewKeySheetCollection(title string, numOfCopies uint16, numOfDays uint16) *KeySheetCollection {
	res := new(KeySheetCollection)
	res.Title = title
	res.NumberOfCopies = numOfCopies
	res.NumberOfDays = numOfDays
	res.Copies = []*KeySheet{}
	res.SeedLen = SeedLength
	res.deriver = cbmcrypt.NewCBMDeriver(nil)

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
			seedRaw[i] = petscii.IndexToPetscii(seedRaw[i])
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
		fmt.Print(petscii.SliceToString(j.KeySeed))
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

	rendererMap := map[string]RenderFunc{defaultRendererName: keySheets.DiagnosticRenderer}

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
