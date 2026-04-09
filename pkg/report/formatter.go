package report

import (
	"fmt"
	"io"

	"github.com/Shasheen8/Broly/pkg/core"
)

var Version = "dev"

type Formatter interface {
	Format(w io.Writer, result *core.ScanResult) error
	Name() string
}

func GetFormatter(format string) (Formatter, error) {
	switch format {
	case "json":
		return &JSONFormatter{}, nil
	case "sarif":
		return &SARIFFormatter{Version: Version}, nil
	case "table", "":
		return &TableFormatter{}, nil
	default:
		return nil, fmt.Errorf("unsupported output format %q (use: table, json, sarif)", format)
	}
}
