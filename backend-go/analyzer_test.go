package main

import (
	"strings"
	"testing"
)

func TestAnalyzeMalformedAttackPaths(t *testing.T) {
	log := "172.16.12.1 - - [31/Oct/2017:15:11:30 +0800] \"GET /uploads/%uff0e%uff0e/etc/passwd HTTP/1.1\" 403 12 \"-\" \"scanner\"\n" +
		"172.16.12.1 - - [31/Oct/2017:15:11:31 +0800] \"GET /search?q=%C0%AE%ZZ<script HTTP/1.1\" 200 12 \"-\" \"scanner\""
	result, err := AnalyzeLog(strings.NewReader(log))
	if err != nil {
		t.Fatal(err)
	}
	if result.ParsedCount != 2 {
		t.Fatalf("parsed=%d", result.ParsedCount)
	}
	if result.CategoryCount["Path traversal"] == 0 || result.CategoryCount["Cross-site scripting"] == 0 {
		t.Fatalf("unexpected categories: %#v", result.CategoryCount)
	}
}
