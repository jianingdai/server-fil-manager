package web

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var files embed.FS

func Files() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
