package parser

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzParse feeds arbitrary bytes through Parse, which expands aliases, merge
// keys and !reference tags, and through the traversal helpers every rule uses.
// A panic or a hang here aborts the whole scan.
func FuzzParse(f *testing.F) {
	addFixtureSeeds(f, filepath.Join("..", "..", "testdata", "fixtures"))
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := Parse(data, "fuzz.yml")
		if err != nil {
			return
		}
		m := doc.MappingNode()
		if m.Kind == yaml.MappingNode {
			IncludeItems(FindKey(m, "include"))
		}
		CountJobs(doc.Root)
		EachJob(doc.Root, func(_, job *yaml.Node) {
			RunStepBlocks(job)
		})
	})
}

func addFixtureSeeds(f *testing.F, dir string) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		f.Fatal(err)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p) //nolint:gosec // G304: test reads the repository's own fixtures
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
}
