// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

// Package inventory lists what a pipeline pulls in, container images and
// includes, as a CycloneDX bill of materials (#830). It reads only the file
// it is given: includes are listed, not fetched.
package inventory

import (
	"regexp"
	"sort"
	"strings"

	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/rules"
	"gopkg.in/yaml.v3"
)

// Kind is what a component is.
type Kind string

const (
	KindImage     Kind = "image"
	KindService   Kind = "service"
	KindComponent Kind = "component"
	KindProject   Kind = "project"
	KindRemote    Kind = "remote"
	KindTemplate  Kind = "template"
)

// Pinning says how firmly a reference is fixed.
type Pinning string

const (
	PinDigest     Pinning = "digest"     // image@sha256:…, or a remote include with integrity:
	PinSHA        Pinning = "sha"        // a full commit SHA
	PinVersion    Pinning = "version"    // an exact version or tag that doesn't move by convention
	PinMutable    Pinning = "mutable"    // latest, a branch name, ~latest, or a partial version
	PinNone       Pinning = "none"       // no tag or ref at all
	PinUnresolved Pinning = "unresolved" // contains a CI variable
	PinGitLab     Pinning = "gitlab"     // a template: include, versioned with GitLab itself
)

// Item is one thing the pipeline pulls in.
type Item struct {
	Kind    Kind
	Ref     string // as written, e.g. "node:20.11.0" or "gitlab.com/g/p/c@1.2.0"
	Name    string // image or component path, project, URL or template name
	Version string // tag, digest, ref or component version; empty if none
	Pinning Pinning
	Files   []string // project includes: the files taken from the project
	Jobs    []string // images and services: the jobs that use it
	Line    int      // first place it appears
}

var (
	fullSHARe  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	exactVerRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.-]+)?$`)
	// partialTagRe matches a tag that names a major or minor release, such as
	// 17, 3.22 or 20-alpine: it moves to each new patch release.
	partialTagRe = regexp.MustCompile(`^v?\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?$`)
	variableRef  = regexp.MustCompile(`\$\{?[A-Za-z_]|\$\[\[`)
)

// Collect returns the images, services and includes of doc, merged by
// reference and sorted by kind, reference and version.
func Collect(doc *parser.Document) []Item {
	c := collector{items: map[string]*Item{}}
	root := doc.Root
	mapping := doc.MappingNode()
	c.includes(parser.FindKey(mapping, "include"))

	in := rules.NewInheritance(root)
	parser.EachJob(root, func(name, job *yaml.Node) {
		if strings.HasPrefix(name.Value, ".") {
			return // hidden jobs don't run; the jobs extending them do
		}
		if trigger := parser.FindKey(job, "trigger"); trigger != nil {
			c.includes(parser.FindKey(trigger, "include"))
			return
		}
		image := in.Key(job, "image")
		if image == nil {
			image = parser.FindKey(mapping, "image") // top-level image:, deprecated but valid
		}
		c.image(KindImage, image, name.Value)
		services := in.Key(job, "services")
		if services == nil {
			services = parser.FindKey(mapping, "services")
		}
		if services != nil && services.Kind == yaml.SequenceNode {
			for _, s := range services.Content {
				c.image(KindService, s, name.Value)
			}
		}
	})

	out := make([]Item, 0, len(c.items))
	for _, it := range c.items {
		sort.Strings(it.Jobs)
		sort.Strings(it.Files)
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Ref != out[j].Ref {
			return out[i].Ref < out[j].Ref
		}
		return out[i].Version < out[j].Version
	})
	return out
}

type collector struct {
	items map[string]*Item
}

func (c *collector) add(it Item, job string) {
	key := string(it.Kind) + "\x00" + it.Ref
	if it.Kind == KindProject {
		key += "\x00" + it.Version
	}
	got, ok := c.items[key]
	if !ok {
		got = &it
		got.Files = append([]string(nil), it.Files...)
		c.items[key] = got
	} else {
		for _, f := range it.Files {
			if !contains(got.Files, f) {
				got.Files = append(got.Files, f)
			}
		}
	}
	if job != "" && !contains(got.Jobs, job) {
		got.Jobs = append(got.Jobs, job)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (c *collector) image(kind Kind, node *yaml.Node, job string) {
	if node == nil {
		return
	}
	ref := node
	if node.Kind == yaml.MappingNode {
		ref = parser.FindKey(node, "name")
	}
	if ref == nil || ref.Kind != yaml.ScalarNode || ref.Value == "" {
		return
	}
	name, version, pin := splitImage(ref.Value)
	c.add(Item{Kind: kind, Ref: ref.Value, Name: name, Version: version, Pinning: pin, Line: ref.Line}, job)
}

// splitImage splits an image reference into name and tag or digest.
func splitImage(ref string) (name, version string, pin Pinning) {
	if variableRef.MatchString(ref) {
		name, version, _ = splitImageParts(ref)
		return name, version, PinUnresolved
	}
	name, version, digest := splitImageParts(ref)
	switch {
	case digest:
		return name, version, PinDigest
	case version == "":
		return name, "", PinNone
	case rules.IsMutableImageTag(version), partialTagRe.MatchString(version):
		return name, version, PinMutable
	default:
		return name, version, PinVersion
	}
}

func splitImageParts(ref string) (name, version string, digest bool) {
	if at := strings.Index(ref, "@"); at >= 0 {
		// name:tag@sha256:… pins by digest; the tag is only a label then.
		base := ref[:at]
		if colon := strings.LastIndex(base, ":"); colon > strings.LastIndex(base, "/") {
			base = base[:colon]
		}
		return base, ref[at+1:], true
	}
	if colon := strings.LastIndex(ref, ":"); colon > strings.LastIndex(ref, "/") {
		return ref[:colon], ref[colon+1:], false
	}
	return ref, "", false
}

func (c *collector) includes(include *yaml.Node) {
	for _, item := range parser.IncludeItems(include) {
		switch {
		case parser.FindKey(item, "component") != nil:
			c.component(parser.FindKey(item, "component"))
		case parser.FindKey(item, "project") != nil:
			c.project(item)
		case parser.FindKey(item, "remote") != nil:
			c.remote(item)
		case parser.FindKey(item, "template") != nil:
			t := parser.FindKey(item, "template")
			if t.Kind == yaml.ScalarNode {
				c.add(Item{Kind: KindTemplate, Ref: t.Value, Name: t.Value, Pinning: pinVar(t.Value, PinGitLab), Line: t.Line}, "")
			}
		}
		// local: and artifact: includes come from the repository or the
		// pipeline itself, not from outside.
	}
}

func pinVar(value string, otherwise Pinning) Pinning {
	if variableRef.MatchString(value) {
		return PinUnresolved
	}
	return otherwise
}

func (c *collector) component(node *yaml.Node) {
	if node.Kind != yaml.ScalarNode {
		return
	}
	name, version := node.Value, ""
	if at := strings.LastIndex(node.Value, "@"); at >= 0 {
		name, version = node.Value[:at], node.Value[at+1:]
	}
	var pin Pinning
	switch {
	case variableRef.MatchString(node.Value):
		pin = PinUnresolved
	case version == "":
		pin = PinNone
	case fullSHARe.MatchString(version):
		pin = PinSHA
	case exactVerRe.MatchString(version):
		pin = PinVersion
	default: // ~latest, a partial version such as 1 or 1.2, or a branch
		pin = PinMutable
	}
	c.add(Item{Kind: KindComponent, Ref: node.Value, Name: name, Version: version, Pinning: pin, Line: node.Line}, "")
}

func (c *collector) project(item *yaml.Node) {
	project := parser.FindKey(item, "project")
	if project.Kind != yaml.ScalarNode {
		return
	}
	var version string
	if ref := parser.FindKey(item, "ref"); ref != nil && ref.Kind == yaml.ScalarNode {
		version = ref.Value
	}
	var files []string
	if f := parser.FindKey(item, "file"); f != nil {
		switch f.Kind {
		case yaml.ScalarNode:
			files = []string{f.Value}
		case yaml.SequenceNode:
			for _, x := range f.Content {
				if x.Kind == yaml.ScalarNode {
					files = append(files, x.Value)
				}
			}
		}
	}
	var pin Pinning
	switch {
	case variableRef.MatchString(project.Value + " " + version):
		pin = PinUnresolved
	case version == "":
		pin = PinNone
	case fullSHARe.MatchString(version):
		pin = PinSHA
	case rules.IsMutableRef(version):
		pin = PinMutable
	default: // a tag or a branch glsec doesn't know; GitLab can't tell either from the name
		pin = PinVersion
	}
	c.add(Item{Kind: KindProject, Ref: project.Value, Name: project.Value, Version: version, Pinning: pin, Files: files, Line: project.Line}, "")
}

func (c *collector) remote(item *yaml.Node) {
	remote := parser.FindKey(item, "remote")
	if remote.Kind != yaml.ScalarNode {
		return
	}
	pin := PinNone
	if parser.FindKey(item, "integrity") != nil {
		pin = PinDigest
	}
	c.add(Item{Kind: KindRemote, Ref: remote.Value, Name: remote.Value, Pinning: pinVar(remote.Value, pin), Line: remote.Line}, "")
}
