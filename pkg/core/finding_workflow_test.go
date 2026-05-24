package core

import "testing"

func TestComputeBaselineMatchKeyWorkflowStableAcrossLineDrift(t *testing.T) {
	a := Finding{
		Type:     ScanTypeWorkflow,
		RuleID:   "zizmor.unpinned-uses",
		FilePath: ".github/workflows/ci.yml",
		StartLine: 10,
	}
	b := a
	b.StartLine = 13

	a.ComputeBaselineMatchKey()
	b.ComputeBaselineMatchKey()

	if a.BaselineMatchKey == "" {
		t.Fatal("expected workflow baseline key")
	}
	if a.BaselineMatchKey != b.BaselineMatchKey {
		t.Fatal("expected workflow baseline key to tolerate minor line drift")
	}
}
