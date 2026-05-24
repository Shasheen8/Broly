package core

import "testing"

func TestScanTypeLabelWorkflow(t *testing.T) {
	if ScanTypeWorkflow.Label() != "GH Actions" {
		t.Fatalf("label = %q", ScanTypeWorkflow.Label())
	}
}
