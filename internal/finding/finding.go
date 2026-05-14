package finding

type Severity string

const (
	Error Severity = "error"
	Warn  Severity = "warn"
	Info  Severity = "info"
)

type Finding struct {
	RuleID   string
	Severity Severity
	Message  string
	File     string
	Line     int
	Col      int
}
