// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// CycloneDX JSON, version 1.6: https://cyclonedx.org/docs/1.6/json/
type bom struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     bomMetadata  `json:"metadata"`
	Components   []component  `json:"components"`
	Dependencies []dependency `json:"dependencies"`
}

type bomMetadata struct {
	Tools     bomTools  `json:"tools"`
	Component component `json:"component"`
}

type bomTools struct {
	Components []component `json:"components"`
}

type component struct {
	Type               string        `json:"type"`
	BOMRef             string        `json:"bom-ref,omitempty"`
	Name               string        `json:"name"`
	Version            string        `json:"version,omitempty"`
	PURL               string        `json:"purl,omitempty"`
	ExternalReferences []externalRef `json:"externalReferences,omitempty"`
	Properties         []property    `json:"properties,omitempty"`
}

type externalRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

const pipelineRef = "pipeline"

// WriteCycloneDX writes items as a CycloneDX 1.6 JSON BOM for the pipeline
// file. The output depends only on its input: there is no timestamp, and the
// serial number is derived from the content, so an unchanged pipeline gives
// a byte-identical BOM.
func WriteCycloneDX(w io.Writer, file, glsecVersion string, items []Item) error {
	if glsecVersion == "" {
		glsecVersion = "dev"
	}
	b := bom{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: bomMetadata{
			Tools: bomTools{Components: []component{{
				Type: "application", Name: "glsec", Version: glsecVersion,
				ExternalReferences: []externalRef{{Type: "website", URL: "https://glsec.github.io"}},
			}}},
			Component: component{Type: "file", BOMRef: pipelineRef, Name: file},
		},
		Components:   make([]component, 0, len(items)),
		Dependencies: []dependency{{Ref: pipelineRef, DependsOn: []string{}}},
	}
	for _, it := range items {
		c := toComponent(it)
		b.Components = append(b.Components, c)
		b.Dependencies[0].DependsOn = append(b.Dependencies[0].DependsOn, c.BOMRef)
	}
	content, err := json.Marshal([]any{file, b.Components})
	if err != nil {
		return err
	}
	b.SerialNumber = "urn:uuid:" + contentUUID(content)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

func contentUUID(data []byte) string {
	h := sha256.Sum256(data)
	h[6] = h[6]&0x0f | 0x50
	h[8] = h[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

func toComponent(it Item) component {
	c := component{Name: it.Name, Version: it.Version, BOMRef: string(it.Kind) + ":" + it.Ref}
	switch it.Kind {
	case KindImage, KindService:
		c.Type = "container"
		if it.Pinning != PinUnresolved {
			c.PURL = dockerPURL(it.Name, it.Version)
		}
	case KindProject:
		c.Type = "library"
		if it.Version != "" {
			c.BOMRef += "@" + it.Version
		}
	case KindRemote:
		c.Type = "library"
		c.ExternalReferences = []externalRef{{Type: "distribution", URL: it.Ref}}
	default:
		c.Type = "library"
	}
	c.Properties = append(c.Properties,
		property{Name: "glsec:kind", Value: string(it.Kind)},
		property{Name: "glsec:pinning", Value: string(it.Pinning)},
		property{Name: "glsec:line", Value: strconv.Itoa(it.Line)},
	)
	for _, f := range it.Files {
		c.Properties = append(c.Properties, property{Name: "glsec:file", Value: f})
	}
	for _, j := range it.Jobs {
		c.Properties = append(c.Properties, property{Name: "glsec:job", Value: j})
	}
	return c
}

// dockerPURL returns the package URL of an image, following the purl spec's
// docker type: the registry goes into repository_url unless it is Docker Hub,
// and a Docker Hub image without a namespace is in library/.
func dockerPURL(name, version string) string {
	registry, path := "", name
	if slash := strings.Index(name, "/"); slash >= 0 {
		first := name[:slash]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			registry, path = first, name[slash+1:]
		}
	}
	if registry == "docker.io" || registry == "index.docker.io" {
		registry = ""
	}
	if registry == "" && !strings.Contains(path, "/") {
		path = "library/" + path
	}
	p := "pkg:docker/" + strings.ToLower(path)
	if version != "" {
		p += "@" + strings.ReplaceAll(version, ":", "%3A")
	}
	if registry != "" {
		p += "?repository_url=" + strings.ToLower(registry)
	}
	return p
}
