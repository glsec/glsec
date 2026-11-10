# Accessibility

glsec is a command-line linter for GitLab CI configuration. Everyone, including people who use assistive technology, should be able to run it, read its findings, follow its documentation, and contribute. This statement describes what glsec does for accessibility, how to report a barrier, and what we ask of contributors.

## The command-line tool

glsec is non-interactive: it reads files and prints a report. There is no terminal UI to navigate, so nothing to tab through or get trapped in.

- **Severity is text, never color alone.** Every finding prints its severity as a word (ERROR, WARN, INFO) next to the rule ID and a `file:line` location. Where color is on, it only emphasizes what the text already says.
- **Color is optional, and off where it would get in the way.** glsec honors `NO_COLOR` and the `--no-color` flag, and turns color off by itself when the output is not a terminal, such as a pipe or a file. `FORCE_COLOR` or `CLICOLOR_FORCE` turn it back on.
- **Machine-readable output for assistive tooling and automation.** Besides the text report, glsec writes `json`, `sarif`, `codeclimate`, `junit`, `gitlab-sast`, and a `template` format (`--format`). Each carries the full finding, so a screen reader, editor, or script can present it however suits the reader.
- **Plain-language findings.** A message states the problem and what to do, with a copyable `file:line` location.

## The documentation site

The glsec website (glsec.github.io) is tested on every change against Lighthouse's accessibility audit, which must score 100 on every page, and we work toward [WCAG 2.2 Level AA](https://www.w3.org/TR/WCAG22/). This is an aspirational target, not a claim of verified conformance: an automated check cannot establish that a page is usable, so we also review changes by hand.

## Reporting a barrier

If something about glsec stops you from using it, open an accessibility issue (there is a template for it) or write to the maintainers. Tell us what you were doing, which tool or assistive technology and versions you used, and what got in the way.

## Contributor expectations

When you change how glsec presents output:

- keep the severity in the text, never as color alone;
- keep `NO_COLOR` / `--no-color` and the non-terminal default working;
- keep the structured formats complete, so a reader who cannot use the text report has an equivalent.

For a website change, run the site's accessibility check and review the page with a keyboard. Note in the pull request what you tested and anything you could not.
