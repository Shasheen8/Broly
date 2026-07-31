package prdiff

import "testing"

func TestParsePatch_SingleHunkAddedLines(t *testing.T) {
	patch := "@@ -1,3 +1,4 @@\n line1\n-line2\n+line2modified\n+line3new\n line4"

	diff := ParsePatch(patch)

	for _, line := range []int{2, 3} {
		if !diff.AddedLines[line] {
			t.Errorf("expected line %d to be added, added set: %v", line, diff.AddedLines)
		}
	}
	if diff.AddedLines[1] || diff.AddedLines[4] {
		t.Errorf("unchanged context lines must not be marked added, added set: %v", diff.AddedLines)
	}
}

func TestParsePatch_MultipleHunks(t *testing.T) {
	patch := "@@ -1,2 +1,2 @@\n line1\n-line2\n+line2new\n" +
		"@@ -10,2 +10,3 @@\n line10\n+line11new\n line12"

	diff := ParsePatch(patch)

	for _, line := range []int{2, 11} {
		if !diff.AddedLines[line] {
			t.Errorf("expected line %d to be added, added set: %v", line, diff.AddedLines)
		}
	}
}

func TestParsePatch_NoNewlineAtEOFMarkerIgnored(t *testing.T) {
	patch := "@@ -1,1 +1,1 @@\n-old\n+new\n\\ No newline at end of file"

	diff := ParsePatch(patch)

	if !diff.AddedLines[1] {
		t.Errorf("expected line 1 to be added, added set: %v", diff.AddedLines)
	}
}

func TestParsePatch_EmptyPatch(t *testing.T) {
	diff := ParsePatch("")

	if len(diff.AddedLines) != 0 {
		t.Errorf("expected no added lines for empty patch, got: %v", diff.AddedLines)
	}
}

func TestParsePatch_MalformedHunkHeaderIgnored(t *testing.T) {
	patch := "@@ -garbage @@\n+should not be counted"

	diff := ParsePatch(patch)

	if len(diff.AddedLines) != 0 {
		t.Errorf("expected malformed hunk header to add nothing, got: %v", diff.AddedLines)
	}
}

func TestFileDiff_HasLine(t *testing.T) {
	diff := &FileDiff{AddedLines: map[int]bool{5: true, 9: true}}

	cases := []struct {
		name        string
		startLine   int
		endLine     int
		wantHasLine bool
	}{
		{"exact match", 5, 5, true},
		{"range covers added line", 3, 6, true},
		{"range misses added lines", 1, 4, false},
		{"endLine before startLine treated as single line", 9, 0, true},
		{"line zero is never in diff", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := diff.HasLine(tc.startLine, tc.endLine); got != tc.wantHasLine {
				t.Errorf("HasLine(%d, %d) = %v, want %v", tc.startLine, tc.endLine, got, tc.wantHasLine)
			}
		})
	}
}

func TestFileDiff_HasLine_NilReceiver(t *testing.T) {
	var diff *FileDiff

	if diff.HasLine(1, 1) {
		t.Error("nil *FileDiff.HasLine must return false, not panic or return true")
	}
}
