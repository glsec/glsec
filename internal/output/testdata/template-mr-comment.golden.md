### glsec 1.2.3

**2** error, **1** warn, **1** info in 3 file(s), 4 job(s).

| Severity | Rule | Job | Location | Message |
|---|---|---|---|---|
| ERROR | GL001 | ` build ` | ` .gitlab-ci.yml `:3 | ` image "node:latest" uses mutable tag "latest" ` |
| WARN | GL053 |  | ` .gitlab-ci.yml `:1 | ` no top-level workflow:rules ` |
| INFO | GL070 | ` @all ` | ` ci/child.yml `:5 | `` see #1 and `make` `` |
| ERROR | GL011 | ` =HYPERLINK("http://x") ` | ` .gitlab-ci.yml `:7 | ` a\|b <img src=x> *c* "q", d\x0anext \u202eevil ` |

**glsec could not scan every file:**

- ` broken.yml `: ` broken.yml: yaml: line 2: <bad> \| input `
