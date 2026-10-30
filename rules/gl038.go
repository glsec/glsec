// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl038 struct{}

var GL038 = &gl038{}

func (r *gl038) ID() string { return "GL038" }

type credCheck struct {
	tool string
	re   *regexp.Regexp
	msg  string
	// db reports whether the credential goes to a database CLI whose
	// target host can be a job service container, or localhost when the
	// job has services. Only those checks are suppressed for own-service
	// targets (#800, part 1).
	db bool
	// A check whose regexp has a group captures the literal in it; a
	// placeholder such as changeme there is not reported.
}

var credChecks = []credCheck{
	{
		tool: "sqlcmd",
		re:   regexp.MustCompile(`\bsqlcmd\b.*-P\s+["']?[^$"'\s]`),
		msg:  "script passes hardcoded credential to sqlcmd via -P flag — use a masked CI variable instead",
		db:   true,
	},
	{
		tool: "mysql",
		re:   regexp.MustCompile(`\bmysql(?:dump|pump)?\b.*\s-p[A-Za-z0-9!@#%^&*()\[\]{}<>]`),
		msg:  "script passes hardcoded credential to mysql via -p flag — use a masked CI variable instead",
		db:   true,
	},
	{
		tool: "mysql",
		re:   regexp.MustCompile(`\bmysql(?:dump|pump)?\b.*--password=[^$'"\s]`),
		msg:  "script passes hardcoded credential to mysql via --password flag — use a masked CI variable instead",
		db:   true,
	},
	{
		tool: "psql/PGPASSWORD",
		re:   regexp.MustCompile(`PGPASSWORD=[^$'"\s]`),
		msg:  "script passes hardcoded credential via PGPASSWORD — use a masked CI variable instead",
		db:   true,
	},
	{
		tool: "mongosh",
		re:   regexp.MustCompile(`\bmongo(?:sh|dump|restore|import|export)?\b.*--password\s+[^$\s"']`),
		msg:  "script passes hardcoded credential via --password flag — use a masked CI variable instead",
		db:   true,
	},
	{
		// A literal after -p/--password; $VAR, "$VAR", \$VAR (in a heredoc
		// for a remote shell), --password-stdin and another flag are not.
		tool: "docker login",
		re:   regexp.MustCompile(`\b(?:docker|podman)\s+login\b[^;&|\n]*\s(?:-p|--password)(?:\s+|=)["']?[^$"'\s\\-]`),
		msg:  "script passes a hardcoded password to docker login — anyone who can read the repository can use it; store it in a masked CI/CD variable and pipe it to --password-stdin",
	},
	{
		// user:password with a literal password. $VAR or ${VAR} after the
		// colon, user: (curl prompts) and : (Kerberos/NTLM) are not.
		tool: "curl -u",
		re:   regexp.MustCompile(`\bcurl\b[^;&|\n]*\s(?:-u|--user)(?:\s+|=)["']?[^\s"':]*:([^$\s"'\\][^\s"']*)`),
		msg:  "script passes a hardcoded password to curl -u — anyone who can read the repository can use it; use a masked CI/CD variable, e.g. -u \"$API_USER:$API_PASSWORD\"",
	},
	{
		// A literal after Bearer, Basic or Token, not $VAR or <token>.
		tool: "Authorization header",
		re:   regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n]*(?:-H|--header)(?:\s+|=)["']?Authorization:\s*(?:Bearer|Basic|Token)\s+([^$<\s"'\\]{8,})`),
		msg:  "script sends a hardcoded credential in an Authorization header — anyone who can read the repository can use it; use a masked CI/CD variable, e.g. \"Authorization: Bearer $API_TOKEN\"",
	},
	{
		tool: "sed",
		re:   regexp.MustCompile(`\bsed\b.+s/[^/]+/[^/:]*:[^$][^@]*@/`),
		msg:  "script rewrites URL with hardcoded password literal via sed — use a masked CI variable instead",
	},
}

func (r *gl038) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)
	aliases, hasServices := jobServiceAliases(doc, in)
	// The result depends on the job (its services), so visit each job's
	// script blocks separately instead of deduplicating shared sequences.
	EachScriptBlockPerJob(doc, file, func(node *yaml.Node, file, job string) {
		findings = append(findings, checkHardcodedCredScript(node, file, job, aliases[job], hasServices[job])...)
	})
	return findings
}

// jobServiceAliases maps each job name to the hostnames its service
// containers are reachable under: the explicit alias: of each service,
// plus the image-derived hostnames of a service without an alias (see
// imageHosts; e.g. mysql:8.0 is reachable as mysql). Services from the
// job's extends: chain and from default: are included. The second return
// value reports, per job, whether the job has any services at all: only
// a job with services can put them on localhost (see targetsOwnService).
func jobServiceAliases(doc *yaml.Node, in *Inheritance) (map[string]map[string]bool, map[string]bool) {
	out := map[string]map[string]bool{}
	hasServices := map[string]bool{}
	mapping := parser.Unwrap(doc)
	var defServices *yaml.Node
	if def := parser.FindKey(mapping, "default"); def != nil {
		defServices = parser.FindKey(def, "services")
	}
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		hosts := map[string]bool{}
		has := false
		for _, services := range in.Chain(job, "services") {
			if services != nil && services.Kind == yaml.SequenceNode && len(services.Content) > 0 {
				has = true
			}
			collectServiceHosts(services, hosts)
		}
		if defServices != nil && inheritsDefault(job, "services") {
			if defServices.Kind == yaml.SequenceNode && len(defServices.Content) > 0 {
				has = true
			}
			collectServiceHosts(defServices, hosts)
		}
		out[name.Value] = hosts
		hasServices[name.Value] = has
	})
	return out, hasServices
}

func collectServiceHosts(services *yaml.Node, hosts map[string]bool) {
	if services == nil || services.Kind != yaml.SequenceNode {
		return
	}
	for _, item := range services.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			for _, h := range imageHosts(item.Value) {
				hosts[h] = true
			}
		case yaml.MappingNode:
			if alias := parser.FindKey(item, "alias"); alias != nil && alias.Kind == yaml.ScalarNode {
				hosts[strings.ToLower(alias.Value)] = true
			}
			if name := parser.FindKey(item, "name"); name != nil && name.Kind == yaml.ScalarNode {
				for _, h := range imageHosts(name.Value) {
					hosts[h] = true
				}
			}
		}
	}
}

// imageHosts returns the hostnames an image reference can be reached under.
// GitLab derives them from the whole image name with the tag stripped and
// every "/" replaced by "__" or "-": registry.example.com/team/mysql is
// reachable as registry.example.com__team__mysql and
// registry.example.com-team-mysql. Only an image without a slash, like
// mysql:8.0, is reachable under its bare name. The last path component
// of a namespaced image is therefore NOT a hostname for it.
func imageHosts(ref string) []string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	// Strip a tag, but only when it follows the last path component.
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i:], "/") {
		ref = ref[:i]
	}
	ref = strings.ToLower(ref)
	if !strings.Contains(ref, "/") {
		return []string{ref}
	}
	return []string{
		strings.ReplaceAll(ref, "/", "__"),
		strings.ReplaceAll(ref, "/", "-"),
	}
}

// hostOptionRe extracts the host values named by database CLI host options
// in a script item: -h / --host (mysql, psql, mongosh), -S (sqlcmd) and
// PGHOST (psql). hostOptionAttachedRe covers the attached short forms
// (-hmysql, -Smssql).
var hostOptionRe = regexp.MustCompile(`(?:^|[\s;&|])(?:-h|-S|--host|PGHOST)(?:\s+|=)\s*["']?([^\s;&|"']+)`)
var hostOptionAttachedRe = regexp.MustCompile(`(?:^|[\s;&|])-[hS]["']?([^\s;&|"']+)`)

var localHosts = map[string]bool{
	"localhost": true,
	"127.0.0.1": true,
	"::1":       true,
}

// targetsOwnService reports whether every host option in the script item
// names a service container of the job or, when the job has services, a
// loopback host, and at least one host option is present. On a shell
// executor, common on self-hosted runners, localhost is the runner machine,
// so a credential to localhost in a job without services is a real finding:
// only the Kubernetes executor puts services on localhost, and a job with
// services is the case this suppression covers. An item with no host
// option, or one that mixes a local host with an external host, is not
// suppressed: a credential with no explicit target, or one that also
// reaches an external host, stays flagged.
func targetsOwnService(item string, aliases map[string]bool, hasServices bool) bool {
	matches := hostOptionRe.FindAllStringSubmatch(item, -1)
	matches = append(matches, hostOptionAttachedRe.FindAllStringSubmatch(item, -1)...)
	if len(matches) == 0 {
		return false
	}
	for _, m := range matches {
		host := normalizeHost(m[1])
		if localHosts[host] {
			if !hasServices {
				return false
			}
			continue
		}
		if !aliases[host] {
			return false
		}
	}
	return true
}

// normalizeHost strips a connection prefix (tcp:, np:), a port (host:port
// or host,port as sqlcmd uses) and an instance suffix (host\instance),
// and lowercases the result.
func normalizeHost(host string) string {
	host = strings.Trim(host, `"'`)
	host = strings.TrimPrefix(strings.ToLower(host), "tcp:")
	host = strings.TrimPrefix(host, "np:")
	host = strings.TrimPrefix(host, "lpc:")
	host = strings.Trim(host, "[]")
	if i := strings.Index(host, `\`); i >= 0 {
		host = host[:i]
	}
	if i := strings.Index(host, ","); i >= 0 {
		host = host[:i]
	}
	// A single colon separates a port; several colons mean an IPv6 address.
	if strings.Count(host, ":") == 1 {
		host = host[:strings.Index(host, ":")]
	}
	return host
}

func checkHardcodedCredScript(node *yaml.Node, file, job string, aliases map[string]bool, hasServices bool) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		reported := false
		for _, check := range credChecks {
			m := check.re.FindStringSubmatchIndex(item.Value)
			if m == nil || (len(m) > 2 && looksLikePlaceholder(item.Value[m[2]:m[3]])) {
				continue
			}
			if check.db && targetsOwnService(item.Value, aliases, hasServices) {
				// The credential only reaches the job's own service
				// container or localhost: keep looking for another
				// (non-suppressed) check in the same item.
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL038",
				Severity: finding.Error,
				Job:      job,
				Message:  fmt.Sprintf("[%s] %s", check.tool, check.msg),
				File:     file,
				Line:     parser.ScalarOffsetLine(item, credentialOffset(m)),
				Col:      item.Column,
			})
			reported = true
			break
		}
		if name, off, ok := exportedSecret(item.Value); ok && !reported {
			findings = append(findings, finding.Finding{
				RuleID:   "GL038",
				Severity: finding.Error,
				Job:      job,
				Message:  fmt.Sprintf("[export] script sets %q, a secret-like name, to a hardcoded value — anyone who can read the repository can use it; store it as a masked CI/CD variable, which the job gets without an export", name),
				File:     file,
				Line:     parser.ScalarOffsetLine(item, off),
				Col:      item.Column,
			})
		}
	}
	return findings
}

// credentialOffset returns where a credCheck match's literal starts: its
// group, or else the last byte of the match, which every pattern ends on the
// literal's first character. The finding goes on that line of a multi-line
// script (#800).
func credentialOffset(m []int) int {
	if len(m) > 2 {
		return m[2]
	}
	return m[1] - 1
}

// secretAssignmentRe matches a shell assignment in command position: at the start
// of a command, or after export. An assignment inside an argument, such as
// --build-arg API_KEY=…, is not one (GL059 covers build args).
var secretAssignmentRe = regexp.MustCompile(`(?:^|[;&|(]\s*|\bexport\s+)([A-Za-z_][A-Za-z0-9_]*)=("[^"$]*"|'[^']*'|[^\s;&|"'$]*)(?:[\s;&|)]|$)`)

// exportedSecret reports whether a script line assigns a literal to a
// variable with a secret-like name (#910), with the name GL027 would use and
// its placeholder handling, and returns the name and where it starts. Values that are rarely a secret are left out: a
// reference ($VAR, $(cmd)), a path or URL, and a short or single-kind value
// such as root, 1 or postgres, which are mostly throwaway passwords for
// service containers.
func exportedSecret(line string) (name string, off int, ok bool) {
	for _, m := range secretAssignmentRe.FindAllStringSubmatchIndex(line, -1) {
		name, v := line[m[2]:m[3]], strings.Trim(line[m[4]:m[5]], `"'`)
		if !hasSecretSuffix(name) || !committedSecretValue(v) || strings.ContainsAny(v, "/~`\\") {
			continue
		}
		mixed := strings.ContainsAny(v, "0123456789") && strings.IndexFunc(v, isLetter) >= 0
		if len(v) < 8 || (!mixed && len(v) < 16) || wordLike(v) {
			continue
		}
		return name, m[2], true
	}
	return "", 0, false
}

func isLetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

// wordLike reports whether v is words or numbers joined by -, _ or ., such
// as ruby-32-pg-coverage or test_secret_value: an identifier, a label or a
// throwaway passphrase, not a generated secret, whose parts mix letters and
// digits.
func wordLike(v string) bool {
	parts := strings.FieldsFunc(v, func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		p = strings.TrimRight(p, "!?#%*+")
		letters := strings.IndexFunc(p, func(r rune) bool { return !isLetter(r) }) < 0
		digits := strings.IndexFunc(p, func(r rune) bool { return r < '0' || r > '9' }) < 0
		if p == "" || (!letters && !digits) {
			return false
		}
	}
	return true
}
