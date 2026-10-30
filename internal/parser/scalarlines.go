// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"runtime"
	"sync"
	"unicode/utf8"
	"weak"

	"gopkg.in/yaml.v3"
)

// A plain, quoted or folded scalar spanning several source lines folds them:
// a line break becomes a space, a blank line a "\n". The node only records
// where the scalar starts, so Parse traces each value byte back to its source
// line while it still has the source (#753, #800). The table is keyed weakly,
// so an entry goes away with its node.
var scalarLines sync.Map // weak.Pointer[yaml.Node] -> []int32

func storeScalarLines(n *yaml.Node, lines []int32) {
	key := weak.Make(n)
	scalarLines.Store(key, lines)
	runtime.AddCleanup(n, func(k weak.Pointer[yaml.Node]) { scalarLines.Delete(k) }, key)
}

func loadScalarLines(n *yaml.Node) []int32 {
	v, ok := scalarLines.Load(weak.Make(n))
	if !ok {
		return nil
	}
	return v.([]int32)
}

// copyScalarLines gives a copy of a node the source lines of the original.
func copyScalarLines(from, to *yaml.Node) {
	if lines := loadScalarLines(from); lines != nil {
		storeScalarLines(to, lines)
	}
}

// recordScalarLines records the source lines of every multi-line scalar
// below n that isn't a literal block; a literal block keeps its lines one to
// one, which ScalarContentLine handles without a table.
// It runs before ExpandAliases, while the nodes still form a tree.
func recordScalarLines(n *yaml.Node, src *sourceLines) {
	if n == nil {
		return
	}
	if n.Kind == yaml.ScalarNode {
		if n.Style&yaml.LiteralStyle == 0 && len(n.Value) > 0 {
			if lines := src.trace(n); lines != nil {
				storeScalarLines(n, lines)
			}
		}
		return
	}
	for _, c := range n.Content {
		recordScalarLines(c, src)
	}
}

type sourceLines struct {
	data   []byte
	starts []int // byte offset of each line; line n starts at starts[n-1]
}

func newSourceLines(data []byte) *sourceLines {
	s := &sourceLines{data: data, starts: []int{0}}
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '\n':
			s.starts = append(s.starts, i+1)
		case '\r':
			// yaml.v3 counts a lone CR as a line break too.
			if i+1 < len(data) && data[i+1] == '\n' {
				i++
			}
			s.starts = append(s.starts, i+1)
		}
	}
	return s
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// trace returns the source line of each byte of n's value, or nil if the
// scalar is on one line or its value can't be matched to the source. Folding
// only drops and inserts whitespace, so the value's other bytes appear in the
// source in the same order; an escape in a quoted scalar ("\n", ”) breaks
// that, and such a scalar keeps the start line. A whitespace byte gets the
// line of the byte after it.
func (s *sourceLines) trace(n *yaml.Node) []int32 {
	line := n.Line
	if line < 1 || line > len(s.starts) {
		return nil
	}
	pos := s.starts[line-1]
	switch {
	case n.Style&yaml.FoldedStyle != 0:
		if line >= len(s.starts) {
			return nil
		}
		line++
		pos = s.starts[line-1]
	default:
		// Column counts characters, not bytes.
		for c := 1; c < n.Column && pos < len(s.data); c++ {
			_, w := utf8.DecodeRune(s.data[pos:])
			pos += w
		}
		if n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0 {
			pos++
		}
	}
	// Two passes: the first checks that the scalar spans several lines and
	// matches the source, so a one-line scalar allocates nothing.
	var lines []int32
	for pass := 0; pass < 2; pass++ {
		p, l, multi := pos, line, false
		for i := 0; i < len(n.Value); i++ {
			c := n.Value[i]
			if isSpace(c) {
				continue
			}
			for p < len(s.data) && isSpace(s.data[p]) {
				p++
			}
			if p >= len(s.data) || s.data[p] != c {
				return nil
			}
			for l < len(s.starts) && s.starts[l] <= p {
				l++
			}
			if l != line {
				multi = true
			}
			if lines != nil {
				lines[i] = int32(l) //nolint:gosec // G115: a line number fits, files are at most MaxFileSize
			}
			p++
		}
		if !multi {
			return nil
		}
		if lines == nil {
			lines = make([]int32, len(n.Value))
			continue
		}
	}
	next := int32(line) //nolint:gosec // G115: as above
	for i := len(lines) - 1; i >= 0; i-- {
		if !isSpace(n.Value[i]) {
			next = lines[i]
			break
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if isSpace(n.Value[i]) {
			lines[i] = next
		} else {
			next = lines[i]
		}
	}
	return lines
}

// ScalarOffsetLine returns the source line of the byte at offset off in a
// scalar node's value.
func ScalarOffsetLine(node *yaml.Node, off int) int {
	if node.Style&yaml.LiteralStyle != 0 {
		line := node.Line + 1
		for i := 0; i < off && i < len(node.Value); i++ {
			if node.Value[i] == '\n' {
				line++
			}
		}
		return line
	}
	if lines := loadScalarLines(node); lines != nil && off >= 0 {
		return int(lines[min(off, len(lines)-1)])
	}
	if node.Style&yaml.FoldedStyle != 0 {
		return node.Line + 1
	}
	return node.Line
}
