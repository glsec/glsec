// Pins benchstat for the Benchmarks workflow (#880): the workflow builds it
// from this module, so its version and hashes come from go.sum and Dependabot
// updates them.

module github.com/glsec/glsec/.github/tools/benchstat

go 1.26.0

tool golang.org/x/perf/cmd/benchstat

require (
	github.com/aclements/go-moremath v0.0.0-20210112150236-f10218a38794 // indirect
	golang.org/x/perf v0.0.0-20261009192801-be2c69fb417e // indirect
)
