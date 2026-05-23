package triage

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Shasheen8/Broly/pkg/ai"
	"github.com/Shasheen8/Broly/pkg/core"
)

const (
	promptVersionSAST             = "sast-v1"
	promptVersionSASTExplain      = "sast-explain-v1"
	promptVersionWorkflow         = "workflow-v1"
	promptVersionWorkflowExplain  = "workflow-explain-v1"
	promptVersionSCA              = "sca-v1"
	promptVersionSCAExplain       = "sca-explain-v1"
	promptVersionContainer        = "container-v1"
	promptVersionContainerExplain = "container-explain-v1"
)

func safeAbsPath(cloneDir, relPath string) string {
	if cloneDir == "" {
		return relPath
	}
	joined := filepath.Join(cloneDir, relPath)
	if !strings.HasPrefix(joined, cloneDir+string(filepath.Separator)) && joined != cloneDir {
		return ""
	}
	return joined
}

// vulnExample holds a BAD/GOOD code pair for a vulnerability class.
// Sourced from sec-context anti-pattern research.
type vulnExample struct {
	keywords []string
	bad      string
	good     string
}

var vulnExamples = []vulnExample{
	// Keywords match both prefilter rule names and LLM finding descriptions.
	// Kept specific to avoid injecting misleading examples on legitimate use
	// (e.g. bare "md5" would match SHA1 cert fingerprinting or git object hashing).
	{
		keywords: []string{"sql injection", "sql string concatenation", "sql f-string", "sql format", "sql concat"},
		bad:      `query = "SELECT * FROM users WHERE id = " + user_id`,
		good:     `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
	},
	{
		keywords: []string{"command injection", "shell command with concat", "os command injection", "shell=true"},
		bad:      `os.system("ping " + host)`,
		good:     `subprocess.run(["ping", host], shell=False)`,
	},
	{
		keywords: []string{"xss", "cross-site scripting", "innerhtml assignment"},
		bad:      `element.innerHTML = userInput`,
		good:     `element.textContent = userInput`,
	},
	{
		keywords: []string{"hardcoded secret", "hardcoded password", "hardcoded credential", "hardcoded api key", "hardcoded token", "aws access key", "private key block", "jwt secret"},
		bad:      `password = "mysecret123"`,
		good:     `password = os.environ["DB_PASSWORD"]`,
	},
	{
		keywords: []string{"path traversal", "path concatenation", "directory traversal"},
		bad:      `open("/uploads/" + filename)`,
		good:     `safe = os.path.realpath(os.path.join("/uploads", filename))\nassert safe.startswith("/uploads")`,
	},
	{
		keywords: []string{"weak hash", "weak hash (md5)", "weak hash (sha1)", "insecure hash"},
		bad:      `hashlib.md5(password.encode()).hexdigest()`,
		good:     `hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)`,
	},
	{
		keywords: []string{"insecure deserialization", "unsafe deserialization"},
		bad:      `data = pickle.loads(user_input)`,
		good:     `data = json.loads(user_input)`,
	},
	{
		keywords: []string{"open redirect", "url redirect", "unvalidated redirect"},
		bad:      `return redirect(request.args.get("next"))`,
		good:     `next_url = request.args.get("next")\nif next_url and is_safe_url(next_url):\n    return redirect(next_url)`,
	},
	{
		keywords: []string{"debug mode enabled"},
		bad:      `app.run(debug=True)`,
		good:     `app.run(debug=os.environ.get("DEBUG", "false").lower() == "true")`,
	},
	{
		keywords: []string{"cors allow all"},
		bad:      `response.headers["Access-Control-Allow-Origin"] = "*"`,
		good:     `response.headers["Access-Control-Allow-Origin"] = "https://trusted.example.com"`,
	},
	{
		keywords: []string{"ecb mode", "aes ecb", "cipher ecb"},
		bad:      `cipher = AES.new(key, AES.MODE_ECB)`,
		good:     `cipher = AES.new(key, AES.MODE_GCM)`,
	},
	{
		keywords: []string{"math.random for security", "weak random", "insecure random"},
		bad:      `token = Math.random().toString(36)`,
		good:     `token = crypto.randomBytes(32).toString("hex")`,
	},
	{
		keywords: []string{"ssrf", "server-side request forgery", "unvalidated url"},
		bad:      `resp = requests.get(request.args["url"])`,
		good:     `url = request.args["url"]\nif not is_allowed_host(url):\n    abort(400)\nresp = requests.get(url)`,
	},
	{
		keywords: []string{"xxe", "xml external entity", "xml injection"},
		bad:      `tree = lxml.etree.parse(user_file)`,
		good:     `parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True)\ntree = lxml.etree.parse(user_file, parser)`,
	},
}

// pickBadGoodExample returns a formatted BAD/GOOD example block for the finding,
// or an empty string if no matching example exists.
func pickBadGoodExample(f *core.Finding) string {
	needle := strings.ToLower(f.RuleName + " " + f.Description)
	for _, ex := range vulnExamples {
		for _, kw := range ex.keywords {
			if strings.Contains(needle, kw) {
				return fmt.Sprintf(
					"\nVulnerability pattern example:\nBAD:  %s\nGOOD: %s\n",
					ex.bad, ex.good,
				)
			}
		}
	}
	return ""
}

// buildSASTTriagePrompt constructs the triage prompt for SAST/secrets/dockerfile findings.
func buildSASTTriagePrompt(f *core.Finding, codeCtx string, explain bool) string {
	var sb strings.Builder

	sb.WriteString("You are a security expert triaging a code vulnerability finding.\n\n")
	fmt.Fprintf(&sb, "Scanner:     %s\n", f.Type)
	fmt.Fprintf(&sb, "Rule:        %s\n", f.RuleName)
	if strings.HasPrefix(f.RuleID, "broly.prefilter.") {
		sb.WriteString("Detection:   deterministic regex match (low false-positive rate — bias toward TRUE_POSITIVE)\n")
	}
	fmt.Fprintf(&sb, "Severity:    %s\n", f.Severity.String())
	fmt.Fprintf(&sb, "Description: %s\n", f.Description)
	fmt.Fprintf(&sb, "File:        %s:%d\n\n", f.FilePath, f.StartLine)
	sb.WriteString("Code context:\n```\n")
	sb.WriteString(codeCtx)
	sb.WriteString("\n```\n")

	if example := pickBadGoodExample(f); example != "" {
		sb.WriteString(example)
	}

	sb.WriteString(`
Triage rules — read carefully:
- Default verdict is TRUE_POSITIVE. Only emit FALSE_POSITIVE when the visible code is provably safe.
- A FALSE_POSITIVE verdict requires HIGH confidence backed by concrete visible-code evidence. If you would mark FALSE_POSITIVE with LOW or MEDIUM confidence, mark TRUE_POSITIVE instead — uncertainty is not enough to dismiss a flagged vulnerability.
- Treat any function parameter, request value, environment variable, or external input as attacker-controllable unless the visible code sanitizes it before reaching the sink.
- Do NOT FP based on filename or directory (e.g. "test.py", "examples/", "fixtures/"). Security-test fixtures are intentionally vulnerable and must be reported.
- Do NOT FP because the function isn't called from an obvious entry point in the visible slice — cross-file reachability is not visible to you.
- Concrete FP patterns (these ARE false positives):
  * The value being interpolated/concatenated is a hardcoded string literal, not a variable.
  * The "secret" is an obvious placeholder (e.g., "REPLACE_ME", "TODO", all-zero key, well-known docs example used to demo the API).
  * The detected operation is not actually a sink (e.g., the SQL string is logged or returned as text but never executed).

Fix guidance constraints:
- Use the exact identifiers and APIs visible in the provided code.
- Keep the fix targeted to this file and the vulnerable code path shown.
- Do not invent placeholder helper names, generic wrappers, or pseudocode.
- If the provided context is insufficient for a safe code-specific fix, say so plainly in CODE_FIX instead of giving generic advice.

Respond with exactly:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE
CONFIDENCE: HIGH or MEDIUM or LOW
REASON: One sentence.`)

	if explain {
		sb.WriteString("\nEXPLANATION: One sentence. Concrete attack vector and real-world impact specific to this code — not generic advice.")
	}
	sb.WriteString("\nRECOMMENDATION: One short sentence with the minimal targeted remediation for this file.")
	sb.WriteString("\nCODE_FIX:\n<2-8 lines of corrected code using local identifiers, or a one-sentence limitation if the context is too incomplete, or N/A if false positive>")

	return sb.String()
}

func buildWorkflowTriagePrompt(f *core.Finding, codeCtx string, explain bool) string {
	var sb strings.Builder

	sb.WriteString("You are a security expert triaging a GitHub Actions workflow finding from zizmor.\n\n")
	fmt.Fprintf(&sb, "Scanner:     GH Actions (zizmor)\n")
	fmt.Fprintf(&sb, "Rule:        %s\n", f.RuleName)
	fmt.Fprintf(&sb, "Severity:    %s\n", f.Severity.String())
	fmt.Fprintf(&sb, "Description: %s\n", f.Description)
	if f.FilePath != "" {
		fmt.Fprintf(&sb, "File:        %s:%d\n", f.FilePath, f.StartLine)
	}
	if len(f.References) > 0 {
		fmt.Fprintf(&sb, "Reference:   %s\n", f.References[0])
	}
	if strings.TrimSpace(f.Snippet) != "" {
		fmt.Fprintf(&sb, "\nFlagged step fragment:\n```yaml\n%s\n```\n", strings.TrimSpace(f.Snippet))
	}
	if strings.TrimSpace(codeCtx) != "" {
		sb.WriteString("\nWorkflow context:\n```yaml\n")
		sb.WriteString(codeCtx)
		sb.WriteString("\n```\n")
	}

	sb.WriteString(`
Triage rules:
- These findings come from static GitHub Actions analysis. Default to TRUE_POSITIVE unless the visible YAML clearly shows the flagged issue is already remediated.
- Only emit FALSE_POSITIVE with HIGH confidence when the workflow already pins actions to immutable SHAs, scopes permissions correctly, or otherwise fixes the issue in the visible YAML.

Fix guidance constraints:
- Recommend the smallest safe workflow YAML change for this file.
- Prefer pinning actions to full commit SHAs, tightening permissions, and removing unsafe patterns.
- Use valid GitHub Actions YAML in CODE_FIX.
- Do not invent composite actions or files that are not visible in the provided context.
- If the context is incomplete, say so in CODE_FIX instead of giving generic advice.

Respond with exactly:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE
CONFIDENCE: HIGH or MEDIUM or LOW
REASON: One sentence.`)

	if explain {
		sb.WriteString("\nEXPLANATION: One sentence. Concrete abuse scenario for this workflow misconfiguration.")
	}
	sb.WriteString("\nRECOMMENDATION: One short sentence with the minimal targeted remediation for this workflow file.")
	sb.WriteString("\nCODE_FIX:\n<valid GitHub Actions YAML snippet for the corrected step/job, or N/A if false positive>")

	return sb.String()
}

type Triager struct {
	client   *ai.Client
	explain  bool
	cloneDir string
}

func New(model string, explain bool, cloneDir string) *Triager {
	c, ok := ai.New(model)
	if !ok {
		return nil
	}
	return &Triager{client: c, explain: explain, cloneDir: cloneDir}
}

func (t *Triager) ModelName() string {
	if t == nil || t.client == nil {
		return ""
	}
	return t.client.ModelName()
}

func (t *Triager) PromptVersion(f core.Finding) string {
	if t == nil {
		return ""
	}
	return PromptVersion(f, t.explain)
}

func (t *Triager) PromptHash(f core.Finding) string {
	if t == nil {
		return ""
	}
	prompt := promptForFinding(&f, t.explain, t.cloneDir)
	sum := sha256.Sum256([]byte(prompt))
	return fmt.Sprintf("%x", sum[:])
}

func (t *Triager) Run(ctx context.Context, findings []core.Finding) []core.Finding {
	out := make([]core.Finding, len(findings))
	copy(out, findings)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	for i := range out {
		if !Eligible(out[i]) {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			verdict, confidence, reason, explanation, recommendation, codeFix := triageFinding(ctx, t.client, &out[i], t.explain, t.cloneDir)
			out[i].Verdict = verdict
			out[i].Confidence = confidence
			out[i].VerdictReason = reason
			out[i].Explanation = explanation
			if recommendation != "" {
				out[i].FixSuggestion = recommendation
			}
			out[i].FixCode = codeFix
		}(i)
	}
	wg.Wait()
	return out
}

func PromptVersion(f core.Finding, explain bool) string {
	switch f.Type {
	case core.ScanTypeContainer:
		if explain {
			return promptVersionContainerExplain
		}
		return promptVersionContainer
	case core.ScanTypeSCA:
		if explain {
			return promptVersionSCAExplain
		}
		return promptVersionSCA
	case core.ScanTypeWorkflow:
		if explain {
			return promptVersionWorkflowExplain
		}
		return promptVersionWorkflow
	default:
		if explain {
			return promptVersionSASTExplain
		}
		return promptVersionSAST
	}
}

func promptForFinding(f *core.Finding, explain bool, cloneDir string) string {
	var prompt string

	switch f.Type {
	case core.ScanTypeContainer:
		prompt = buildContainerPrompt(f, explain)
	case core.ScanTypeSCA:
		prompt = buildSCAPrompt(f, explain)
	case core.ScanTypeWorkflow:
		var codeCtx string
		absPath := safeAbsPath(cloneDir, f.FilePath)
		if absPath != "" {
			codeCtx = core.FileContext(absPath, f.StartLine, 12)
		}
		prompt = buildWorkflowTriagePrompt(f, codeCtx, explain)
	default:
		var codeCtx string
		absPath := safeAbsPath(cloneDir, f.FilePath)
		if f.Type == core.ScanTypeSecrets {
			if absPath == "" {
				codeCtx = fmt.Sprintf("detected value (redacted): %s", f.Redacted)
			} else {
				codeCtx = fmt.Sprintf("detected value (redacted): %s\n\nsurrounding code context:\n%s", f.Redacted, core.FileContextSafe(absPath, f.StartLine, f.EndLine, 8))
			}
		} else {
			if absPath != "" {
				codeCtx = core.FileContext(absPath, f.StartLine, 8)
			}
		}
		prompt = buildSASTTriagePrompt(f, codeCtx, explain)
	}
	return prompt
}

func triageFinding(ctx context.Context, client *ai.Client, f *core.Finding, explain bool, cloneDir string) (verdict, confidence, reason, explanation, recommendation, codeFix string) {
	prompt := promptForFinding(f, explain, cloneDir)
	resp, err := client.Complete(ctx, prompt, 4096)
	if err != nil {
		return "", "", "AI triage unavailable: " + err.Error(), "", "", ""
	}

	verdict, confidence, reason, explanation, recommendation, codeFix = parseTriageResponse(resp)

	// Deterministic prefilter regex matches have a near-zero FP rate by
	// construction. Don't let an AI verdict that isn't HIGH-confidence flip a
	// genuine critical to FALSE_POSITIVE — require strong evidence to override.
	if strings.HasPrefix(f.RuleID, "broly.prefilter.") &&
		verdict == "FALSE_POSITIVE" && confidence != "HIGH" {
		verdict = "TRUE_POSITIVE"
		reason = "Deterministic regex match; AI triage lacked HIGH-confidence evidence to override. " + reason
	}
	return verdict, confidence, reason, explanation, recommendation, codeFix
}

func buildContainerPrompt(f *core.Finding, explain bool) string {
	fixInfo := "Fixed in: " + f.FixedVersion
	if f.FixedVersion == "" {
		fixInfo = "No patched version available."
	}

	var explainLine string
	if explain {
		explainLine = "\nEXPLANATION: One sentence. Concrete attack scenario specific to this package vulnerability."
	}

	return fmt.Sprintf(`You are a security expert triaging a container image vulnerability.

Vulnerability: %s
Package:       %s@%s
Ecosystem:     %s
Severity:      %s
Description:   %s
CVE:           %s
%s

Triage rules:
- Default verdict is TRUE_POSITIVE. A vulnerable package in a container image is a real risk even if the vulnerable code path is not obviously called from the app — runtime dependencies, init scripts, or transitive calls may reach it.
- Only mark FALSE_POSITIVE with HIGH confidence if the vulnerability is explicitly in a dev-only or test-only package that cannot be reached at runtime, or the CVE has been disputed/withdrawn.
- Do NOT mark FALSE_POSITIVE just because the package "might not be used" — container packages are typically present for a reason.

Respond with exactly:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE
CONFIDENCE: HIGH or MEDIUM or LOW
REASON: One sentence.%s
FIX:
<mitigation or upgrade command, or N/A if false positive>`,
		f.RuleID,
		f.PackageName, f.PackageVersion,
		f.Ecosystem,
		f.Severity.String(),
		f.Description,
		f.CVE,
		fixInfo,
		explainLine,
	)
}

func buildSCAPrompt(f *core.Finding, explain bool) string {
	fixInfo := "Fixed in: " + f.FixedVersion
	if f.FixedVersion == "" {
		fixInfo = "No patched version available."
	}

	var explainLine string
	if explain {
		explainLine = "\nEXPLANATION: One sentence. Concrete attack scenario for this dependency vulnerability."
	}

	return fmt.Sprintf(`You are a security expert triaging a dependency vulnerability in a software project.

Vulnerability: %s
Package:       %s@%s
Ecosystem:     %s
Severity:      %s
Description:   %s
CVE:           %s
Lockfile:      %s
%s

Triage rules:
- Default verdict is TRUE_POSITIVE. A vulnerable dependency is a real risk unless you have HIGH-confidence evidence that the vulnerable function is unreachable.
- Only mark FALSE_POSITIVE with HIGH confidence when: the vulnerability is in an optional/test-dev-only dependency not included in production builds, or the CVE has been disputed/withdrawn, or the lockfile is for a separate workspace/module that doesn't use this package at runtime.
- Do NOT mark FALSE_POSITIVE because "the vulnerable function might not be called" — without call-graph proof, that is speculation.

Respond with exactly:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE
CONFIDENCE: HIGH or MEDIUM or LOW
REASON: One sentence.%s
FIX:
<upgrade command or workaround, or N/A if false positive>`,
		f.RuleID,
		f.PackageName, f.PackageVersion,
		f.Ecosystem,
		f.Severity.String(),
		f.Description,
		f.CVE,
		f.FilePath,
		fixInfo,
		explainLine,
	)
}

func parseTriageResponse(resp string) (verdict, confidence, reason, explanation, recommendation, codeFix string) {
	var fixLines []string
	inCodeFix := false
	sawCodeFix := false

	for _, line := range strings.Split(resp, "\n") {
		trimmed := strings.TrimSpace(line)
		label, val, hasLabel := triageLabelValue(trimmed)
		upperVal := strings.ToUpper(val)

		if hasLabel && label == "VERDICT" {
			normalized := strings.ReplaceAll(upperVal, " ", "_")
			normalized = strings.ReplaceAll(normalized, "-", "_")
			if strings.Contains(normalized, "FALSE_POSITIVE") {
				verdict = "FALSE_POSITIVE"
			} else if strings.Contains(normalized, "TRUE_POSITIVE") {
				verdict = "TRUE_POSITIVE"
			}
			inCodeFix = false
			continue
		}
		if hasLabel && label == "CONFIDENCE" {
			switch {
			case strings.Contains(upperVal, "HIGH"):
				confidence = "HIGH"
			case strings.Contains(upperVal, "MEDIUM"):
				confidence = "MEDIUM"
			case strings.Contains(upperVal, "LOW"):
				confidence = "LOW"
			}
			inCodeFix = false
			continue
		}
		if hasLabel && label == "REASON" {
			reason = val
			inCodeFix = false
			continue
		}
		if hasLabel && label == "EXPLANATION" {
			explanation = val
			inCodeFix = false
			continue
		}
		if hasLabel && label == "RECOMMENDATION" {
			recommendation = val
			inCodeFix = false
			continue
		}
		if hasLabel && label == "CODE_FIX" {
			if val != "" && upperVal != "N/A" && !isCodeFence(val) {
				var keepCollecting bool
				fixLines, keepCollecting = appendFixLine(fixLines, val)
				if !keepCollecting {
					inCodeFix = false
					continue
				}
			}
			inCodeFix = true
			sawCodeFix = true
			continue
		}
		if hasLabel && label == "FIX" {
			if val != "" && upperVal != "N/A" && !isCodeFence(val) {
				if !looksLikeReasoningLine(val) {
					if recommendation != "" {
						recommendation += "\n" + strings.TrimSpace(val)
					} else {
						recommendation = strings.TrimSpace(val)
					}
				}
			}
			inCodeFix = false
			continue
		}
		if inCodeFix && isCodeFence(trimmed) {
			if len(fixLines) > 0 {
				inCodeFix = false
			}
			continue
		}
		if inCodeFix && trimmed != "" && strings.ToUpper(trimmed) != "N/A" && !isCodeFence(trimmed) {
			var keepCollecting bool
			fixLines, keepCollecting = appendFixLine(fixLines, trimmed)
			if !keepCollecting {
				inCodeFix = false
			}
			if inCodeFix && len(fixLines) >= 8 {
				inCodeFix = false
			}
		}
	}

	if sawCodeFix {
		codeFix = strings.Join(fixLines, "\n")
		return verdict, confidence, reason, explanation, recommendation, codeFix
	}
	recommendation = strings.Join(fixLines, "\n")
	return verdict, confidence, reason, explanation, recommendation, ""
}

func triageLabelValue(line string) (label, value string, ok bool) {
	s := strings.TrimSpace(line)
	if len(s) >= 2 && (strings.HasPrefix(s, "- ") || strings.HasPrefix(s, "* ")) {
		s = strings.TrimSpace(s[1:])
	}
	idx := strings.Index(s, ":")
	if idx < 0 {
		return "", "", false
	}
	label = strings.TrimSpace(s[:idx])
	label = strings.TrimSpace(strings.Trim(label, "`*"))
	label = strings.ToUpper(label)
	label = strings.ReplaceAll(label, "-", "_")
	label = strings.ReplaceAll(label, " ", "_")
	value = strings.TrimSpace(s[idx+1:])
	value = strings.TrimSpace(strings.Trim(value, "`*"))
	return label, value, label != ""
}

func isCodeFence(s string) bool {
	return strings.HasPrefix(s, "```")
}

func appendFixLine(lines []string, line string) ([]string, bool) {
	trimmed := strings.TrimSpace(line)
	if looksLikeReasoningLine(trimmed) {
		return lines, false
	}
	return append(lines, trimmed), true
}

func looksLikeReasoningLine(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(strings.TrimLeft(line, "*- ")))
	markers := []string{
		"actually",
		"assuming",
		"best fix",
		"constraint check",
		"decision:",
		"final review",
		"however",
		"i need",
		"let me",
		"line ",
		"need to",
		"or simply",
		"re-reading",
		"requires ",
		"since ",
		"the code",
		"the context",
		"the fix",
		"the instruction",
		"the prompt",
		"this ",
		"wait",
	}
	for _, marker := range markers {
		if strings.HasPrefix(lower, marker) {
			return true
		}
	}
	return false
}
