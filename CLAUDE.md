# Claude Instructions

## Commit messages

- Keep commit messages brief (one short line), prefixed `<type>:` or `<type>(<scope>):` (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`)
- No `Co-Authored-By:` trailer — omit it entirely
- Sign off every commit (`git commit -s`): the DCO check blocks commits without `Signed-off-by:` (#610)
- Detailed context belongs in the pull request description, not the commit

## Pull requests

- PR descriptions should be thorough: what changed, why, how to test
- One branch per issue, named `<type>/issue-<N>-<slug>`; a change without an issue uses `<type>/<slug>`

## Working on an issue

Treat the issue as a hypothesis to test, not a spec to fill. glsec's value is precision, so the thinking matters more than the diff.

- Before coding, restate the problem in your own words and check the premise against the primary source (GitLab CI YAML reference, variable constraints, runner behaviour, the actual attack). If it doesn't hold, say so and propose the correction instead of implementing a rule you've shown to be wrong.
- Hunt the counter-evidence: a realistic benign config that trips the change (false positive), the findings a fix could silently drop (must-stay-reported), a simpler or more general approach, an existing rule or helper in `rules/helpers.go`/`rules/shell.go` that already covers it.
- For any rule add or change, measure against real pipelines and put the finding delta (added/removed, true vs false positive) in the PR. Don't claim corpus-clean from unit tests.
- Put the reasoning in the PR description: what you considered and rejected, the scope boundary (what it deliberately doesn't flag), the tradeoffs. "Implements #N" is not a description.
- Disagreeing with the issue, backed by evidence, is wanted. Raise it rather than quietly building the wrong thing.

## General

- No comments unless the why is non-obvious
- No trailing summaries in responses — output speaks for itself
