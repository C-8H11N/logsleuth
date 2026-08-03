package main

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Finding struct {
	ID        int    `json:"id"`
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	Evidence  string `json:"evidence"`
}

type AnalysisResult struct {
	ParsedCount   int             `json:"parsedCount"`
	Unreadable    int             `json:"unreadableLines"`
	Findings      []Finding       `json:"findings"`
	CategoryCount map[string]int  `json:"categoryCount"`
	SourceCount   map[string]int  `json:"sourceCount"`
	Sessions      []AttackSession `json:"sessions"`
}

type parsedLog struct {
	timestamp, ip, method, path, raw string
	status                           int
}
type rule struct {
	category, severity string
	pattern            *regexp.Regexp
}

var (
	linePattern  = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)(\s+[^"\s]+)?"\s+(\d{3})`)
	legacyEscape = regexp.MustCompile(`(?i)%u([0-9a-f]{4})`)
	loginPattern = regexp.MustCompile(`(?i)/(login|auth|sign-in|wp-login)`)
	rules        = []rule{
		{"SQL injection", "Critical", regexp.MustCompile(`(?i)(union(\s+all)?\s+select|select.+from|\bor\s+['"]?1['"]?\s*=\s*['"]?1|sleep\s*\(|benchmark\s*\(|information_schema)`)},
		{"Cross-site scripting", "High", regexp.MustCompile(`(?i)(<script|%3cscript|onerror\s*=|onload\s*=|javascript:|alert\s*\()`)},
		{"Path traversal", "High", regexp.MustCompile(`(?i)(\.\./(\.\./)?|\.\.\\|%2e%2e%2f|/etc/passwd|win\.ini)`)},
		{"Sensitive-file probing", "Medium", regexp.MustCompile(`(?i)(\.env(\.|$)|\.git(/|$)|id_rsa|wp-config\.php|\.bak(\?|$)|backup\.(zip|sql))`)},
		{"Command-injection probe", "High", regexp.MustCompile(`(?i)(;\s*(cat|whoami|id|curl|wget)\b|\|\s*(cat|whoami|id)\b|\$\{(IFS|PATH))`)},
		{"Log4Shell/JNDI probe", "Critical", regexp.MustCompile(`(?i)(\$\{jndi:(ldap|rmi|dns|iiop):)`)},
		{"Web shell probing", "High", regexp.MustCompile(`(?i)(/|%2f)(shell|cmd|upload|backdoor|wso|c99|r57)\.(php|jsp|asp|aspx)(\?|$)`)},
		{"SSRF probe", "High", regexp.MustCompile(`(?i)(url|uri|target|dest|redirect)=https?%?3a(%2f|/){2}(127\.0\.0\.1|localhost|169\.254\.169\.254|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)`)},
	}
)

func safeDecode(value string) string {
	legacy := legacyEscape.ReplaceAllStringFunc(value, func(match string) string {
		code, err := strconv.ParseInt(match[2:], 16, 32)
		if err != nil {
			return match
		}
		return string(rune(code))
	})
	decoded, err := url.PathUnescape(legacy)
	if err != nil {
		return value + "\n" + legacy
	}
	return value + "\n" + decoded
}

func parseLogLine(raw string) (parsedLog, bool) {
	m := linePattern.FindStringSubmatch(raw)
	if len(m) != 7 {
		return parsedLog{}, false
	}
	status, _ := strconv.Atoi(m[6])
	return parsedLog{ip: m[1], timestamp: m[2], method: m[3], path: m[4], status: status, raw: raw}, true
}

func AnalyzeLog(reader io.Reader) (AnalysisResult, error) {
	result := AnalysisResult{Findings: []Finding{}, CategoryCount: map[string]int{}, SourceCount: map[string]int{}}
	loginAttempts := map[string][]parsedLog{}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		entry, ok := parseLogLine(scanner.Text())
		if !ok {
			result.Unreadable++
			continue
		}
		result.ParsedCount++
		detection := safeDecode(entry.path)
		for _, candidate := range rules {
			if candidate.pattern.MatchString(detection) {
				finding := Finding{ID: len(result.Findings) + 1, Timestamp: entry.timestamp, IP: entry.ip, Method: entry.method, Path: entry.path, Status: entry.status, Category: candidate.category, Severity: candidate.severity, Evidence: entry.raw}
				result.Findings = append(result.Findings, finding)
				result.CategoryCount[candidate.category]++
				result.SourceCount[entry.ip]++
			}
		}
		if loginPattern.MatchString(entry.path) {
			loginAttempts[entry.ip] = append(loginAttempts[entry.ip], entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("read log: %w", err)
	}
	for ip, attempts := range loginAttempts {
		if len(attempts) < 3 {
			continue
		}
		last := attempts[len(attempts)-1]
		finding := Finding{ID: len(result.Findings) + 1, Timestamp: last.timestamp, IP: ip, Method: last.method, Path: last.path, Status: last.status, Category: "Suspected credential attack", Severity: "High", Evidence: fmt.Sprintf("%d login requests from %s", len(attempts), ip)}
		result.Findings = append(result.Findings, finding)
		result.CategoryCount[finding.Category]++
		result.SourceCount[ip]++
	}
	sort.SliceStable(result.Findings, func(i, j int) bool {
		left, right := findingTime(result.Findings[i].Timestamp), findingTime(result.Findings[j].Timestamp)
		if !left.IsZero() && !right.IsZero() {
			return left.Before(right)
		}
		return strings.Compare(result.Findings[i].Timestamp, result.Findings[j].Timestamp) < 0
	})
	result.Sessions = CorrelateSessions(result.Findings)
	return result, nil
}
