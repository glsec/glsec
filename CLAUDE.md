# Claude Instructions

## Commit messages
- Keep commit messages brief (one short line), prefixed `<type>:` or `<type>(<scope>):` (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`)
- No `Co-Authored-By:` trailer — omit it entirely
- Sign off every commit (`git commit -s`): the DCO check blocks commits without `Signed-off-by:` (#610)
- Detailed context belongs in the pull request description, not the commit

## Pull requests
- PR descriptions should be thorough: what changed, why, how to test
- One branch per issue, named `<type>/issue-<N>-<slug>`; a change without an issue uses `<type>/<slug>`

## General
- No comments unless the why is non-obvious
- No trailing summaries in responses — output speaks for itself
