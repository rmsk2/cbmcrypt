// Package sheet implements generating key sheets for CBMCrypt
package sheet

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"keygen/cbmcrypt"
	"keygen/petscii"
)

// SeedLength holds the default seed length in characters
var SeedLength uint16 = 16

// RenderFunc is a type that abstracts a thing that knows how to render a key sheet
type RenderFunc func(k *KeySheet) error

// KeySheetEntry represents an entry in a key sheet that describes the key for a specific day on a
// specific copy
type KeySheetEntry struct {
	KeySeed     []byte // KeySeed holds the key value if the entry
	KeyID       []byte // KeyID holds an identifier of the key which can be used when decrypting a message
	NoncePrefix []byte // NoncePrefix holds a prefix for the nonce that is specific for the copy and the day
	CheckValue  []byte // CheckValue can be used to check whether the user has entered all key data correctly
}

// NewKeySheetEntry creates and initializes a new key sheet entry
func NewKeySheetEntry(seed []byte, keyID []byte, noncePrefix []byte, checkValue []byte) *KeySheetEntry {
	res := new(KeySheetEntry)
	res.KeySeed = seed
	res.KeyID = keyID
	res.NoncePrefix = noncePrefix
	res.CheckValue = checkValue

	return res
}

// KeySheet holds all components of a key sheet
type KeySheet struct {
	Title   string           // Title holds the title of the key sheet
	CopyID  uint16           // CopyID is the unique identifier of this key sheet copy
	Entries []*KeySheetEntry // Entries holds the Entries of the key sheet
}

// NewKeySheet creates and initializes a new key sheet
func NewKeySheet(title string, copyID uint16) *KeySheet {
	res := new(KeySheet)
	res.Title = title
	res.CopyID = copyID
	res.Entries = []*KeySheetEntry{}

	return res
}

// AddEntry appends an entry to a key sheet
func (k *KeySheet) AddEntry(e *KeySheetEntry) {
	k.Entries = append(k.Entries, e)
}

// KeySheetCollection binds together all copies of a key sheet
type KeySheetCollection struct {
	Title          string      // Title holds the title of the key sheet
	NumberOfCopies uint16      // NumberOfCopies stores the number of copies of the key sheet
	NumberOfDays   uint16      // NumberOfDays stores the number of keys which are to appear on each copy
	SeedLen        uint16      // SeedLen holds the number of characters in the key
	Copies         []*KeySheet // Copies points to the collection of copies of the key sheet
	deriver        *cbmcrypt.CBMDeriver
}

// NewKeySheetCollection creates and initializes a key sheet collection
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

// AddCopy appends a new copy to the key sheet collection
func (k *KeySheetCollection) AddCopy(s *KeySheet) {
	k.Copies = append(k.Copies, s)
}

// Generate generates all values on all copies of the key sheet
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
		var copyID uint16 = 0
		for j := range noncePrefixes {
			noncePrefixAsBytes := []byte{0, 0}
			binary.LittleEndian.PutUint16(noncePrefixAsBytes, j)
			customCheckValue := k.deriver.CustomizeCheckValue(checkValue, noncePrefixAsBytes)
			newSheetEntry := NewKeySheetEntry(seedRaw, keyIDAsBytes, noncePrefixAsBytes, customCheckValue)
			k.Copies[copyID].AddEntry(newSheetEntry)

			copyID++
		}
	}

	return nil
}

// RenderAll renders all copies of the key sheet using the specified renderer
func (k *KeySheetCollection) RenderAll(renderer RenderFunc) error {
	for _, j := range k.Copies {
		err := renderer(j)
		if err != nil {
			return fmt.Errorf("unable to render copy %d: %v", j.CopyID, err)
		}
	}
	return nil
}

// DiagnosticRenderer is a primitive renderer that only shows the values but does no formatting. It can
// be used to test the key generation function.
func (k *KeySheetCollection) DiagnosticRenderer(sheet *KeySheet) error {
	fmt.Println(sheet.Title)
	fmt.Printf("Copy Nr.: %d\n", sheet.CopyID+1)
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
