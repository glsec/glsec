// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

// prefiltered is a regexp that first checks, with strings.Contains, for the
// literals every match must contain, and skips the regexp when none is in the
// input. Most script lines don't mention curl, socat or pip at all, and the
// check is far cheaper than the regexp (#870). Methods it doesn't wrap fall
// through to the embedded regexp unfiltered.
type prefiltered struct {
	*regexp.Regexp
	// anyOf lists literals of which every match contains at least one; nil
	// when the expression has no such literal.
	anyOf []string
}

// allPrefiltered collects every prefiltered regexp, so a test can check each
// one gives the same results as the regexp alone.
var allPrefiltered []prefiltered

func mustCompilePrefiltered(expr string) prefiltered {
	re := regexp.MustCompile(expr)
	parsed, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		panic(err) // unreachable: regexp.MustCompile accepted it
	}
	p := prefiltered{re, minimal(requiredLiterals(parsed.Simplify()))}
	allPrefiltered = append(allPrefiltered, p)
	return p
}

// minimal drops every literal that contains another one: a line with
// "nc.openbsd" also contains "nc".
func minimal(lits []string) []string {
	var out []string
	for i, l := range lits {
		if l == "" {
			return nil // every input contains it: no filter
		}
		redundant := false
		for j, o := range lits {
			if i != j && strings.Contains(l, o) && (l != o || j < i) {
				redundant = true
				break
			}
		}
		if !redundant {
			out = append(out, l)
		}
	}
	return out
}

func (p prefiltered) possible(s string) bool {
	if p.anyOf == nil {
		return true
	}
	for _, lit := range p.anyOf {
		if strings.Contains(s, lit) {
			return true
		}
	}
	return false
}

func (p prefiltered) MatchString(s string) bool {
	return p.possible(s) && p.Regexp.MatchString(s)
}

func (p prefiltered) FindString(s string) string {
	if !p.possible(s) {
		return ""
	}
	return p.Regexp.FindString(s)
}

func (p prefiltered) FindStringIndex(s string) []int {
	if !p.possible(s) {
		return nil
	}
	return p.Regexp.FindStringIndex(s)
}

func (p prefiltered) FindAllStringIndex(s string, n int) [][]int {
	if !p.possible(s) {
		return nil
	}
	return p.Regexp.FindAllStringIndex(s, n)
}

func (p prefiltered) FindAllStringSubmatchIndex(s string, n int) [][]int {
	if !p.possible(s) {
		return nil
	}
	return p.Regexp.FindAllStringSubmatchIndex(s, n)
}

func (p prefiltered) ReplaceAllString(src, repl string) string {
	if !p.possible(src) {
		return src
	}
	return p.Regexp.ReplaceAllString(src, repl)
}

// requiredLiterals returns literals of which every match of re contains at
// least one, or nil when it can't name any. Case-insensitive literals give
// nil: strings.Contains can't check them.
func requiredLiterals(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return nil
		}
		return []string{string(re.Rune)}
	// Simplify has rewritten x{n,m} into these, so there is no OpRepeat.
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiterals(re.Sub[0])
	case syntax.OpConcat:
		// Any one part's literals will do; take the set whose shortest
		// literal is longest, the most selective. Neighbouring parts that
		// match a few fixed strings join into whole words: the parser
		// factors nc|ncat|netcat into n(?:c|cat|etcat).
		var best []string
		consider := func(lits []string) {
			if lits != nil && shortest(lits) > shortest(best) {
				best = lits
			}
		}
		var run []string
		for _, sub := range re.Sub {
			set := exactStrings(sub)
			switch {
			case set == nil:
				consider(run)
				run = nil
				consider(requiredLiterals(sub))
			case run == nil:
				run = set
			default:
				if joined := product(run, set); joined != nil {
					run = joined
				} else {
					consider(run)
					run = set
				}
			}
		}
		consider(run)
		return best
	case syntax.OpAlternate:
		var all []string
		for _, sub := range re.Sub {
			lits := requiredLiterals(sub)
			if lits == nil {
				return nil
			}
			all = append(all, lits...)
		}
		return all
	}
	return nil
}

// maxExact caps the strings exactStrings and product expand to, maxClass the
// characters of a class it expands: [23] is worth spelling out, \s is not.
const (
	maxExact = 64
	maxClass = 4
)

// exactStrings returns every string re can match when that is a short list,
// else nil. Zero-width assertions such as \b match the empty string.
func exactStrings(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return nil
		}
		return []string{string(re.Rune)}
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return []string{""}
	case syntax.OpCharClass:
		var out []string
		for i := 0; i < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				if len(out) == maxClass {
					return nil
				}
				out = append(out, string(r))
			}
		}
		return out
	case syntax.OpCapture:
		return exactStrings(re.Sub[0])
	case syntax.OpQuest:
		if set := exactStrings(re.Sub[0]); set != nil && len(set) < maxExact {
			return append([]string{""}, set...)
		}
		return nil
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			set := exactStrings(sub)
			if set == nil || len(out)+len(set) > maxExact {
				return nil
			}
			out = append(out, set...)
		}
		return out
	case syntax.OpConcat:
		out := []string{""}
		for _, sub := range re.Sub {
			set := exactStrings(sub)
			if set == nil {
				return nil
			}
			if out = product(out, set); out == nil {
				return nil
			}
		}
		return out
	}
	return nil
}

// product returns every a+b, or nil when there would be more than maxExact.
func product(as, bs []string) []string {
	if len(as)*len(bs) > maxExact {
		return nil
	}
	out := make([]string, 0, len(as)*len(bs))
	for _, a := range as {
		for _, b := range bs {
			out = append(out, a+b)
		}
	}
	return out
}

// shortest returns the length of the shortest literal, 0 for none. A set
// containing the empty string is useless as a filter and scores 0 too.
func shortest(lits []string) int {
	if lits == nil {
		return 0
	}
	n := len(lits[0])
	for _, l := range lits[1:] {
		n = min(n, len(l))
	}
	return n
}
