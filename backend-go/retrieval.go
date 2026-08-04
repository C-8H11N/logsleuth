package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type ToolTrace struct {
	Name    string `json:"name"`
	Query   string `json:"query"`
	Results int    `json:"results"`
}
type RetrievalInfo struct {
	Findings int         `json:"findings"`
	Sessions int         `json:"sessions"`
	Tools    []ToolTrace `json:"tools"`
}
type RetrievalResult struct {
	Findings []Finding
	Sessions []AttackSession
	Info     RetrievalInfo
}

var evidenceRefPattern = regexp.MustCompile(`(?i)\[?E#(\d+)\]?`)
var sessionRefPattern = regexp.MustCompile(`(?i)\[?S#(\d+)\]?`)
var ipPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
var tokenPattern = regexp.MustCompile(`[A-Za-z0-9_./%-]{3,}`)

func integerRefs(pattern *regexp.Regexp, value string) map[int]bool {
	result := map[int]bool{}
	for _, match := range pattern.FindAllStringSubmatch(value, -1) {
		id, _ := strconv.Atoi(match[1])
		result[id] = true
	}
	return result
}
func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func RetrieveEvidence(question string, findings []Finding, sessions []AttackSession) RetrievalResult {
	lower := strings.ToLower(question)
	evidenceIDs := integerRefs(evidenceRefPattern, question)
	sessionIDs := integerRefs(sessionRefPattern, question)
	ips := map[string]bool{}
	for _, ip := range ipPattern.FindAllString(question, -1) {
		ips[ip] = true
	}
	tokens := tokenPattern.FindAllString(lower, -1)
	scores := make([]struct {
		finding Finding
		score   int
	}, 0, len(findings))
	tools := []ToolTrace{}
	for _, finding := range findings {
		score := 0
		text := strings.ToLower(finding.Category + " " + finding.IP + " " + finding.Method + " " + finding.Path + " " + finding.Severity)
		if evidenceIDs[finding.ID] {
			score += 1000
		}
		if ips[finding.IP] {
			score += 300
		}
		for _, token := range tokens {
			if strings.Contains(text, token) {
				score += 12
			}
		}
		if containsAny(lower, "sql", "注入") && finding.Category == "SQL injection" {
			score += 150
		}
		if containsAny(lower, "xss", "跨站") && finding.Category == "Cross-site scripting" {
			score += 150
		}
		if containsAny(lower, "目录", "穿越", "traversal") && finding.Category == "Path traversal" {
			score += 150
		}
		if containsAny(lower, "登录", "凭据", "login", "credential") && finding.Category == "Suspected credential attack" {
			score += 150
		}
		if containsAny(lower, "成功", "success", "状态码", "status") && finding.Status >= 200 && finding.Status < 400 {
			score += 80
		}
		if strings.EqualFold(finding.Severity, "Critical") {
			score += 15
		}
		if score > 0 {
			scores = append(scores, struct {
				finding Finding
				score   int
			}{finding, score})
		}
	}
	if len(evidenceIDs) > 0 {
		tools = append(tools, ToolTrace{"get_evidence", fmt.Sprintf("%v", keys(evidenceIDs)), len(evidenceIDs)})
	}
	if len(ips) > 0 {
		tools = append(tools, ToolTrace{"search_findings", strings.Join(stringKeys(ips), ","), len(scores)})
	}
	selectedSessions := []AttackSession{}
	sessionEvidence := map[int]bool{}
	for _, session := range sessions {
		selected := sessionIDs[session.ID] || ips[session.IP] || containsAny(lower, "会话", "session", "时间线", "timeline")
		if selected {
			selectedSessions = append(selectedSessions, session)
			for _, id := range session.EvidenceIDs {
				sessionEvidence[id] = true
			}
		}
	}
	if len(sessionIDs) > 0 {
		tools = append(tools, ToolTrace{"get_session", fmt.Sprintf("%v", keys(sessionIDs)), len(selectedSessions)})
	}
	if containsAny(lower, "会话", "session", "时间线", "timeline") {
		tools = append(tools, ToolTrace{"summarize_timeline", question, len(selectedSessions)})
	}
	if containsAny(lower, "成功", "success", "状态码", "status") {
		tools = append(tools, ToolTrace{"count_by_status", question, len(scores)})
	}
	for _, finding := range findings {
		if sessionEvidence[finding.ID] {
			scores = append(scores, struct {
				finding Finding
				score   int
			}{finding, 500})
		}
	}
	if len(scores) == 0 {
		for _, finding := range findings {
			score := severityRank(finding.Severity) * 10
			scores = append(scores, struct {
				finding Finding
				score   int
			}{finding, score})
		}
		tools = append(tools, ToolTrace{"search_findings", "highest severity fallback", len(findings)})
	}
	sort.SliceStable(scores, func(i, j int) bool { return scores[i].score > scores[j].score })
	selected := []Finding{}
	seen := map[int]bool{}
	for _, candidate := range scores {
		if seen[candidate.finding.ID] {
			continue
		}
		seen[candidate.finding.ID] = true
		selected = append(selected, candidate.finding)
		if len(selected) >= 30 {
			break
		}
	}
	if len(selectedSessions) == 0 {
		limit := min(8, len(sessions))
		selectedSessions = append(selectedSessions, sessions[:limit]...)
	}
	if len(selectedSessions) > 12 {
		selectedSessions = selectedSessions[:12]
	}
	return RetrievalResult{Findings: selected, Sessions: selectedSessions, Info: RetrievalInfo{Findings: len(selected), Sessions: len(selectedSessions), Tools: tools}}
}

func ValidateCitations(analysis string, findings []Finding, sessions []AttackSession) (bool, []string) {
	validEvidence := map[int]bool{}
	for _, finding := range findings {
		validEvidence[finding.ID] = true
	}
	validSessions := map[int]bool{}
	for _, session := range sessions {
		validSessions[session.ID] = true
	}
	invalid := []string{}
	seen := map[string]bool{}
	for _, match := range evidenceRefPattern.FindAllStringSubmatch(analysis, -1) {
		id, _ := strconv.Atoi(match[1])
		label := fmt.Sprintf("[E#%d]", id)
		if !validEvidence[id] && !seen[label] {
			invalid = append(invalid, label)
			seen[label] = true
		}
	}
	for _, match := range sessionRefPattern.FindAllStringSubmatch(analysis, -1) {
		id, _ := strconv.Atoi(match[1])
		label := fmt.Sprintf("[S#%d]", id)
		if !validSessions[id] && !seen[label] {
			invalid = append(invalid, label)
			seen[label] = true
		}
	}
	return len(invalid) == 0, invalid
}
func keys(values map[int]bool) []int {
	result := []int{}
	for key := range values {
		result = append(result, key)
	}
	sort.Ints(result)
	return result
}
func stringKeys(values map[string]bool) []string {
	result := []string{}
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
