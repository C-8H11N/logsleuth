package main

import "testing"

func TestRetrieveEvidenceUsesQuestionAndExplicitReferences(t *testing.T) {
	findings := []Finding{{ID: 1, IP: "10.0.0.8", Category: "SQL injection", Severity: "Critical", Path: "/products?id=1", Status: 500}, {ID: 2, IP: "10.0.0.9", Category: "Cross-site scripting", Severity: "High", Path: "/search", Status: 200}, {ID: 3, IP: "10.0.0.8", Category: "Path traversal", Severity: "High", Path: "/etc/passwd", Status: 403}}
	result := RetrieveEvidence("分析 10.0.0.8 的 SQL 注入并查看 E#3", findings, nil)
	if len(result.Findings) != 2 {
		t.Fatalf("findings=%d", len(result.Findings))
	}
	if result.Findings[0].ID != 3 && result.Findings[1].ID != 3 {
		t.Fatal("explicit evidence was not retrieved")
	}
	if len(result.Info.Tools) == 0 {
		t.Fatal("tool trace missing")
	}
}

func TestValidateCitationsRejectsInventedIDs(t *testing.T) {
	valid, invalid := ValidateCitations("依据 [E#1] 和 [S#9]，另见 [E#404]。", []Finding{{ID: 1}}, []AttackSession{{ID: 9}})
	if valid || len(invalid) != 1 || invalid[0] != "[E#404]" {
		t.Fatalf("valid=%v invalid=%v", valid, invalid)
	}
}
