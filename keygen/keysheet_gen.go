package main

import (
	"flag"
	"fmt"
	"keygen/render"
	"keygen/sheet"
)

func main() {
	const defaultRendererName = "default"
	titlePtr := flag.String("title", "Default", "Title of the key sheet")
	numCopiesPtr := flag.Uint("copies", 2, "Number of copies, i.e. number of participants")
	numDaysPtr := flag.Uint("num-keys", 31, "Number of keys on sheet")
	keyLenPtr := flag.Uint("key-len", uint(sheet.SeedLength), "Number of characters in key")
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

	keySheets := sheet.NewKeySheetCollection(*titlePtr, uint16(*numCopiesPtr), uint16(*numDaysPtr))
	keySheets.SeedLen = uint16(*keyLenPtr)

	rendererMap := map[string]sheet.RenderFunc{
		defaultRendererName:     keySheets.DiagnosticRenderer,
		render.TextRendererName: render.NewTextRenderer().RenderStdOut,
		"file":                  render.NewTextRenderer().RenderFile,
	}

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
