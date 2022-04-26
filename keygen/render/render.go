// Package render contains code that knows how to render a CBMCrypt key sheet.
package render

import "keygen/sheet"

// TextRenderer binds all data together which is needed to implement the text renderer
type TextRenderer struct {
}

// NewTextRenderer returns a new initialized TextRenderer struct
func NewTextRenderer() *TextRenderer {
	return nil
}

// Render renders a key sheet as a formatted text file
func (t *TextRenderer) Render(sheet *sheet.KeySheet) error {

	return nil
}
