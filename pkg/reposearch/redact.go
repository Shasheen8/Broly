package reposearch

import (
	"regexp"
)

var secretLinePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token|credential)\s*[:=]\s*\S+`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	regexp.MustCompile(`arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s"'<>]+`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`sk-[A-Za-z0-9-]{20,}`),
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
}

func redactLine(line string) string {
	redacted := line
	for _, re := range secretLinePatterns {
		if re.MatchString(redacted) {
			redacted = re.ReplaceAllString(redacted, "<redacted>")
		}
	}
	return redacted
}

func redactLines(lines []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = redactLine(line)
	}
	return out
}
