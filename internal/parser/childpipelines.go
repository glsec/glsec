package parser

import "gopkg.in/yaml.v3"

// ChildPipelinePaths returns the local file paths referenced by
// trigger: include: in any job in doc. Both forms are handled:
//
//	trigger:
//	  include: child.yml           # scalar shorthand
//
//	trigger:
//	  include:
//	    - local: child.yml         # sequence with local key
//
// Multi-project triggers (trigger: project: ...) are ignored since
// there is no local file to scan.
func ChildPipelinePaths(doc *yaml.Node) []string {
	var paths []string
	EachJob(doc, func(_ *yaml.Node, job *yaml.Node) {
		trigger := FindKey(job, "trigger")
		if trigger == nil || trigger.Kind != yaml.MappingNode {
			return
		}
		include := FindKey(trigger, "include")
		if include == nil {
			return
		}
		switch include.Kind {
		case yaml.ScalarNode:
			if include.Value != "" {
				paths = append(paths, include.Value)
			}
		case yaml.SequenceNode:
			for _, item := range include.Content {
				if item.Kind != yaml.MappingNode {
					continue
				}
				local := FindKey(item, "local")
				if local != nil && local.Value != "" {
					paths = append(paths, local.Value)
				}
			}
		}
	})
	return paths
}
