// Package render contains code that knows how to render a CBMCrypt key sheet.
package render

import (
	"fmt"
	"io"
	"keygen/petscii"
	"keygen/sheet"
	"os"
	"strings"
)

const TextRendererName = "txt"

// TextRenderer binds all data together which is needed to implement the text renderer
type TextRenderer struct {
	ColumnWidth uint16
}

// NewTextRenderer returns a new initialized TextRenderer struct
func NewTextRenderer() *TextRenderer {
	res := new(TextRenderer)
	res.ColumnWidth = 76

	return res
}

func centerWithWidth(txt *string, w uint16) string {
	if len(*txt) >= int(w) {
		return strings.Clone(*txt)
	}

	paddingLen := (w - uint16(len(*txt))) / 2

	return strings.Repeat(" ", int(paddingLen)) + *txt
}

// Render renders a key sheet as formatted text which is written to a io.Writer
func (t *TextRenderer) RenderToWriter(w io.Writer, sheet *sheet.KeySheet) error {
	h := sheet.Entries[0]

	lineLen := uint16(len(fmt.Sprintf("| %s | %04x | %04x | %06x |", petscii.SliceToString(h.KeySeed), h.KeyID, h.NoncePrefix, h.CheckValue)))
	divider := strings.Repeat("-", int(lineLen))

	fmt.Fprintf(w, "%s\n", centerWithWidth(&sheet.Title, lineLen))
	fmt.Fprintln(w)
	copyLine := fmt.Sprintf("Copy Nr. %d", sheet.CopyID)
	fmt.Fprintf(w, "%s\n", centerWithWidth(&copyLine, lineLen))
	fmt.Fprintln(w)

	keyLen := uint16(len(h.KeySeed))
	txtKey := "Key"
	txtKey = centerWithWidth(&txtKey, keyLen)
	padding := strings.Repeat(" ", int(keyLen)-len(txtKey))
	txtKey = txtKey + padding

	fmt.Fprintln(w, divider)
	fmt.Fprintf(w, "| %s |  ID  | Nonc | Check  |\n", txtKey)
	fmt.Fprintln(w, divider)

	for _, j := range sheet.Entries {
		fmt.Fprintf(w, "| %s | %04x | %04x | %06x |\n", petscii.SliceToString(j.KeySeed), j.KeyID, j.NoncePrefix, j.CheckValue)
	}

	fmt.Fprintln(w, divider)
	fmt.Fprintln(w)

	return nil
}

// RenderStdOut renders a key sheet and writes it to stdout
func (t *TextRenderer) RenderStdOut(sheet *sheet.KeySheet) error {
	return t.RenderToWriter(os.Stdout, sheet)
}

// RenderFile renders a key sheet as a formatted text file
func (t *TextRenderer) RenderFile(sheet *sheet.KeySheet) error {
	fileName := fmt.Sprintf("copy_nr_%d.txt", sheet.CopyID)
	f, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("unable to render sheet: %v", err)
	}
	defer func() { f.Close() }()

	return t.RenderToWriter(f, sheet)
}
