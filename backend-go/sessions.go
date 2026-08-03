package main

import (
	"fmt"
	"sort"
	"time"
)

type AttackSession struct {
	ID          int      `json:"id"`
	IP          string   `json:"ip"`
	StartedAt   string   `json:"startedAt"`
	EndedAt     string   `json:"endedAt"`
	Severity    string   `json:"severity"`
	Stages      []string `json:"stages"`
	EvidenceIDs []int    `json:"evidenceIds"`
	Count       int      `json:"count"`
	Confidence  int      `json:"confidence"`
}

const logTimeLayout = "02/Jan/2006:15:04:05 -0700"

func findingTime(value string) time.Time {
	parsed, err := time.Parse(logTimeLayout, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func attackStage(category string) string {
	switch category {
	case "Sensitive-file probing", "Path traversal":
		return "Reconnaissance"
	case "Suspected credential attack":
		return "Credential Access"
	case "Web shell probing":
		return "Persistence"
	case "SQL injection", "Cross-site scripting", "Command-injection probe", "Log4Shell/JNDI probe", "SSRF probe":
		return "Exploitation"
	default:
		return "Suspicious Activity"
	}
}

func severityRank(value string) int {
	switch value {
	case "Critical":
		return 3
	case "High":
		return 2
	default:
		return 1
	}
}

func CorrelateSessions(findings []Finding) []AttackSession {
	bySource := map[string][]Finding{}
	for _, finding := range findings {
		bySource[finding.IP] = append(bySource[finding.IP], finding)
	}
	sessions := []AttackSession{}
	for ip, sourceFindings := range bySource {
		sort.SliceStable(sourceFindings, func(i, j int) bool {
			return findingTime(sourceFindings[i].Timestamp).Before(findingTime(sourceFindings[j].Timestamp))
		})
		var current []Finding
		flush := func() {
			if len(current) == 0 {
				return
			}
			stages, seen := []string{}, map[string]bool{}
			severity, successful := "Medium", false
			evidence := make([]int, 0, len(current))
			for _, finding := range current {
				stage := attackStage(finding.Category)
				if !seen[stage] {
					seen[stage] = true
					stages = append(stages, stage)
				}
				if severityRank(finding.Severity) > severityRank(severity) {
					severity = finding.Severity
				}
				if finding.Status >= 200 && finding.Status < 400 {
					successful = true
				}
				evidence = append(evidence, finding.ID)
			}
			confidence := 30 + min(len(current)*3, 30) + min(len(stages)*8, 24)
			if successful {
				confidence += 8
			}
			confidence = min(confidence, 95)
			sessions = append(sessions, AttackSession{IP: ip, StartedAt: current[0].Timestamp, EndedAt: current[len(current)-1].Timestamp, Severity: severity, Stages: stages, EvidenceIDs: evidence, Count: len(current), Confidence: confidence})
			current = nil
		}
		for _, finding := range sourceFindings {
			if len(current) > 0 {
				previous, next := findingTime(current[len(current)-1].Timestamp), findingTime(finding.Timestamp)
				if !previous.IsZero() && !next.IsZero() && next.Sub(previous) > 30*time.Minute {
					flush()
				}
			}
			current = append(current, finding)
		}
		flush()
	}
	sort.SliceStable(sessions, func(i, j int) bool {
		if sessions[i].Confidence != sessions[j].Confidence {
			return sessions[i].Confidence > sessions[j].Confidence
		}
		return findingTime(sessions[i].StartedAt).Before(findingTime(sessions[j].StartedAt))
	})
	for index := range sessions {
		sessions[index].ID = index + 1
		if sessions[index].StartedAt == sessions[index].EndedAt {
			sessions[index].EndedAt = fmt.Sprintf("%s (single event)", sessions[index].EndedAt)
		}
	}
	return sessions
}
