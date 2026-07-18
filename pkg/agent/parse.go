package agent

import (
	"strings"

	"github.com/Shasheen8/Broly/pkg/reposearch"
)

type Request struct {
	Name string
	Args map[string]string
}

func ParseToolRequests(response string) []Request {
	var out []Request
	for _, line := range strings.Split(response, "\n") {
		if req, ok := parseToolLine(line); ok {
			out = append(out, req)
		}
	}
	return out
}

func parseToolLine(line string) (Request, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return Request{}, false
	}
	upper := strings.ToUpper(trimmed)
	if !strings.HasPrefix(upper, "TOOL:") {
		return Request{}, false
	}
	rest := strings.TrimSpace(trimmed[len("TOOL:"):])
	if rest == "" {
		return Request{}, false
	}

	if open := strings.Index(rest, "("); open > 0 {
		close := strings.LastIndex(rest, ")")
		if close > open {
			name := strings.TrimSpace(rest[:open])
			inner := strings.Trim(strings.TrimSpace(rest[open+1:close]), `"'`)
			return Request{Name: name, Args: quotedArgs(name, inner)}, true
		}
	}

	parts := strings.Fields(rest)
	if len(parts) == 0 {
		return Request{}, false
	}
	name := parts[0]
	args := map[string]string{}
	for _, part := range parts[1:] {
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		args[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(val), `"'`)
	}
	return Request{Name: name, Args: args}, true
}

func quotedArgs(tool, value string) map[string]string {
	args := map[string]string{}
	switch tool {
	case reposearch.ToolCodeSearch:
		args["query"] = value
	case reposearch.ToolFindFiles:
		args["pattern"] = value
	case reposearch.ToolFileRead:
		args["path"] = value
	default:
		args["query"] = value
	}
	return args
}
