package suppress

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// pattern matches:  # glsec:ignore GL001
//
//	# glsec:ignore GL001 -- approved, updated monthly
var pattern = regexp.MustCompile(`glsec:ignore\s+(GL\d{3})(?:\s+--\s+(.+))?`)

// IgnoreFile is the default name of the baseline ignore file written by
// --generate-ignore and read automatically on each run.
const IgnoreFile = ".glsec-ignore"

// Suppression records a single inline suppression parsed from a YAML comment.
type Suppression struct {
	RuleID string
	Reason string // empty when no reason was given
	Line   int
}

// FromNode extracts all suppressions declared in the comments attached to node.
// yaml.v3 attaches inline comments (# …) to the node as LineComment.
func FromNode(node *yaml.Node) []Suppression {
	return fromComment(node.LineComment, node.Line)
}

func fromComment(comment string, line int) []Suppression {
	if comment == "" {
		return nil
	}
	var out []Suppression
	for _, match := range pattern.FindAllStringSubmatch(comment, -1) {
		s := Suppression{RuleID: match[1], Line: line}
		if len(match) > 2 {
			s.Reason = strings.TrimSpace(match[2])
		}
		out = append(out, s)
	}
	return out
}

// Map builds a lookup from (line → set of suppressed rule IDs) for an entire
// YAML document tree. Call this once per document, then use IsSuppressed.
type Map map[int]map[string]string // line → ruleID → reason

// Build walks the node tree and collects all inline suppressions.
func Build(root *yaml.Node) Map {
	m := make(Map)
	walk(root, m)
	return m
}

func walk(node *yaml.Node, m Map) {
	if node == nil {
		return
	}
	for _, s := range fromComment(node.LineComment, node.Line) {
		if m[s.Line] == nil {
			m[s.Line] = make(map[string]string)
		}
		m[s.Line][s.RuleID] = s.Reason
	}
	for _, child := range node.Content {
		walk(child, m)
	}
}

// IsSuppressed returns true when ruleID is suppressed on the given line.
func (m Map) IsSuppressed(line int, ruleID string) bool {
	if rules, ok := m[line]; ok {
		_, suppressed := rules[ruleID]
		return suppressed
	}
	return false
}

// Merge copies all entries from other into m.
func (m Map) Merge(other Map) {
	for line, rules := range other {
		if m[line] == nil {
			m[line] = make(map[string]string)
		}
		for id, reason := range rules {
			m[line][id] = reason
		}
	}
}

// LoadIgnoreFile reads a .glsec-ignore file and returns suppressions for the
// given target file. Entries for other files are silently skipped.
// Returns an empty map if the file does not exist.
func LoadIgnoreFile(ignorePath, targetFile string) Map {
	m := make(Map)
	f, err := os.Open(ignorePath) //nolint:gosec
	if err != nil {
		return m
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// format: <file>:<linenum> <ruleID>
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		loc, ruleID := parts[0], strings.TrimSpace(parts[1])
		lastColon := strings.LastIndex(loc, ":")
		if lastColon < 0 {
			continue
		}
		filePath := loc[:lastColon]
		lineNum, err := strconv.Atoi(loc[lastColon+1:])
		if err != nil || lineNum < 1 {
			continue
		}
		if filePath != targetFile {
			continue
		}
		if m[lineNum] == nil {
			m[lineNum] = make(map[string]string)
		}
		m[lineNum][ruleID] = ""
	}
	return m
}
