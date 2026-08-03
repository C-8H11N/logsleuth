package main

import "testing"

func TestCorrelateSessionsBySourceAndTimeWindow(t *testing.T) {
	findings := []Finding{
		{ID: 1, Timestamp: "31/Oct/2017:15:00:00 +0800", IP: "10.0.0.8", Category: "Sensitive-file probing", Severity: "Medium", Status: 404},
		{ID: 2, Timestamp: "31/Oct/2017:15:05:00 +0800", IP: "10.0.0.8", Category: "SQL injection", Severity: "Critical", Status: 500},
		{ID: 3, Timestamp: "31/Oct/2017:16:00:00 +0800", IP: "10.0.0.8", Category: "Web shell probing", Severity: "High", Status: 200},
	}
	sessions := CorrelateSessions(findings)
	if len(sessions) != 2 {
		t.Fatalf("sessions=%d", len(sessions))
	}
	if sessions[0].Severity != "Critical" || len(sessions[0].Stages) != 2 {
		t.Fatalf("unexpected first session: %#v", sessions[0])
	}
}
