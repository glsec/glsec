package suppress

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// dateLayout is the format accepted for suppression expiry dates.
const dateLayout = "2006-01-02"

// pattern matches:  # glsec:ignore GL001
//
//	# glsec:ignore GL001 -- approved, updated monthly
//	# glsec:ignore GL001 exp:2026-12-01 -- accepted until the migration lands
//	# glsec:ignore SC2086
var pattern = regexp.MustCompile(
	`glsec:ignore\s+((?:GL|SC)\d+)(?:\s+exp:(\d{4}-\d{2}-\d{2}))?(?:\s+--\s+(.+))?`,
)

// IgnoreFile is the default name of the baseline ignore file written by
// --generate-ignore and read automatically on each run.
const IgnoreFile = ".glsec-ignore"

// Entry holds the metadata of a single suppression.
type Entry struct {
	Reason string // empty when no reason was given
	// Expiry is an optional "YYYY-MM-DD" date. Once it has passed, the
	// suppression stops applying and the finding is reported again. Empty means
	// the suppression never expires.
	Expiry string
}

// Expired reports whether the entry has an expiry date that has passed.
// The expiry date itself is inclusive: a suppression dated 2026-12-01 still
// applies throughout that day. A malformed date counts as expired, so a typo
// surfaces the finding rather than silently suppressing it forever.
func (e Entry) Expired(now time.Time) bool {
	if e.Expiry == "" {
		return false
	}
	if _, err := time.Parse(dateLayout, e.Expiry); err != nil {
		return true
	}
	// ISO dates compare lexicographically in chronological order.
	return now.Format(dateLayout) > e.Expiry
}

// Suppression records a single inline suppression parsed from a YAML comment.
type Suppression struct {
	RuleID string
	Reason string // empty when no reason was given
	Expiry string // empty when no expiry was given
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
			s.Expiry = match[2]
		}
		if len(match) > 3 {
			s.Reason = strings.TrimSpace(match[3])
		}
		out = append(out, s)
	}
	return out
}

// Map builds a lookup from (line → ruleID → entry) for an entire YAML document
// tree. Call this once per document, then use IsSuppressed.
type Map map[int]map[string]Entry

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
		m.set(s.Line, s.RuleID, Entry{Reason: s.Reason, Expiry: s.Expiry})
	}
	for _, child := range node.Content {
		walk(child, m)
	}
}

func (m Map) set(line int, ruleID string, e Entry) {
	if m[line] == nil {
		m[line] = make(map[string]Entry)
	}
	m[line][ruleID] = e
}

func (m Map) lookup(line int, ruleID string) (Entry, bool) {
	rules, ok := m[line]
	if !ok {
		return Entry{}, false
	}
	e, ok := rules[ruleID]
	return e, ok
}

// IsSuppressed returns true when ruleID is suppressed on the given line and the
// suppression has not expired as of now.
func (m Map) IsSuppressed(line int, ruleID string, now time.Time) bool {
	e, ok := m.lookup(line, ruleID)
	return ok && !e.Expired(now)
}

// ExpiredAt reports whether a suppression exists for ruleID on the given line
// but has expired, so the finding is reported again. Callers use this to
// explain why a previously silenced finding reappeared.
func (m Map) ExpiredAt(line int, ruleID string, now time.Time) bool {
	e, ok := m.lookup(line, ruleID)
	return ok && e.Expired(now)
}

// Entries returns every suppression in the map, keyed by line and rule ID.
// Used to audit suppressions rather than to evaluate them.
func (m Map) Entries() []Suppression {
	var out []Suppression
	for line, rules := range m {
		for id, e := range rules {
			out = append(out, Suppression{RuleID: id, Reason: e.Reason, Expiry: e.Expiry, Line: line})
		}
	}
	return out
}

// Merge copies all entries from other into m.
func (m Map) Merge(other Map) {
	for line, rules := range other {
		for id, e := range rules {
			m.set(line, id, e)
		}
	}
}

// LoadIgnoreFile reads a .glsec-ignore file and returns suppressions for the
// given target file. Entries for other files are silently skipped.
// Returns an empty map if the file does not exist.
//
// Line format: <file>:<line> <ruleID> [exp:YYYY-MM-DD]
// The expiry token is optional, so files written by earlier versions still load.
func LoadIgnoreFile(ignorePath, targetFile string) Map {
	m := make(Map)
	f, err := os.Open(ignorePath) //nolint:gosec
	if err != nil {
		return m
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		loc, ruleID := fields[0], fields[1]
		expiry := ""
		for _, extra := range fields[2:] {
			if rest, ok := strings.CutPrefix(extra, "exp:"); ok {
				expiry = rest
			}
		}
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
		m.set(lineNum, ruleID, Entry{Expiry: expiry})
	}
	return m
}
