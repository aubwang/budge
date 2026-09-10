package web

import "embed"

//go:embed *.html *.css *.js
var Files embed.FS
