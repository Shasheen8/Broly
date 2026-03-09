package report

import (
	"encoding/json"
	"io"

	"github.com/Shasheen8/Broly/pkg/core"
)

type JSONFormatter struct{}

func (f *JSONFormatter) Name() string { return "json" }

func (f *JSONFormatter) Format(w io.Writer, result *core.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
