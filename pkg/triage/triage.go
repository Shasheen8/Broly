package triage

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Shasheen8/Broly/pkg/ai"
	"github.com/Shasheen8/Broly/pkg/core"
)

// vulnExample holds a BAD/GOOD code pair for a vulnerability class.
// Sourced from sec-context anti-pattern research.
type vulnExample struct {
	keywords []string
	bad      string
	good     string
}

var vulnExamples = []vulnExample{
	{
		keywords: []string{"sql injection", "sql string", "sql format", "sql concat", "sql concatenation"},
		bad:      `query = "SELECT * FROM users WHERE id = " + user_id`,
		good:     `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
	},
	{
		keywords: []string{"command injection", "shell command", "os.system", "exec.command", "os command"},
		bad:      `os.system("ping " + host)`,
		good:     `subprocess.run(["ping", host], shell=False)`,
	},
	{
		keywords: []string{"xss", "cross-site scripting"},
		bad:      `element.innerHTML = userInput`,
		good:     `element.textContent = userInput`,
	},
	{
		keywords: []string{"hardcoded secret", "hardcoded password", "hardcoded credential", "hardcoded api key", "hardcoded token"},
		bad:      `password = "mysecret123"`,
		good:     `password = os.environ["DB_PASSWORD"]`,
	},
	{
		keywords: []string{"path traversal", "path concatenation", "directory traversal"},
		bad:      `open("/uploads/" + filename)`,
		good:     `safe = os.path.realpath(os.path.join("/uploads", filename))\nassert safe.startswith("/uploads")`,
	},
	{
		keywords: []string{"weak hash", "md5", "sha-1", "sha1", "insecure hash"},
		bad:      `hashlib.md5(password.encode()).hexdigest()`,
		good:     `hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)`,
	},
	{
		keywords: []string{"insecure deserialization", "unsafe deserialization", "pickle", "yaml.load"},
		bad:      `data = pickle.loads(user_input)`,
		good:     `data = json.loads(user_input)`,
	},
	{
		keywords: []string{"open redirect", "url redirect", "unvalidated redirect"},
		bad:      `return redirect(request.args.get("next"))`,
		good:     `next_url = request.args.get("next")\nif next_url and is_safe_url(next_url):\n    return redirect(next_url)`,
	},
	{
		keywords: []string{"debug mode", "debug enabled"},
		bad:      `app.run(debug=True)`,
		good:     `app.run(debug=os.environ.get("DEBUG", "false").lower() == "true")`,
	},
	{
		keywords: []string{"cors", "access-control-allow-origin"},
		bad:      `response.headers["Access-Control-Allow-Origin"] = "*"`,
		good:     `response.headers["Access-Control-Allow-Origin"] = "https://trusted.example.com"`,
	},
	{
		keywords: []string{"ecb mode", "aes ecb", "cipher ecb"},
		bad:      `cipher = AES.new(key, AES.MODE_ECB)`,
		good:     `cipher = AES.new(key, AES.MODE_GCM)`,
	},
	{
		keywords: []string{"math.random", "weak random", "insecure random"},
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
Determine:
1. Is this a TRUE_POSITIVE (real, exploitable vulnerability) or FALSE_POSITIVE (test/placeholder/safe pattern)?
2. Your confidence in that verdict.
3. If TRUE_POSITIVE, provide a concrete code fix -- actual code, not advice.

Respond with exactly:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE
CONFIDENCE: HIGH or MEDIUM or LOW
REASON: One sentence.`)

	if explain {
		sb.WriteString("\nEXPLANATION: One sentence. Concrete attack vector and real-world impact specific to this code -- not generic advice.")
	}
	sb.WriteString("\nFIX:\n<2-5 lines of corrected code, or N/A if false positive>")

	return sb.String()
}

type Triager struct {
	client  *ai.Client
	explain bool
}

func New(model string, explain bool) *Triager {
	c, ok := ai.New(model)
	if !ok {
		return nil
	}
	return &Triager{client: c, explain: explain}
}

func (t *Triager) Run(ctx context.Context, findings []core.Finding) []core.Finding {
	out := make([]core.Finding, len(findings))
	copy(out, findings)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	for i := range out {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			verdict, confidence, reason, explanation, fix := triageFinding(ctx, t.client, &out[i], t.explain)
			out[i].Verdict = verdict
			out[i].Confidence = confidence
			out[i].VerdictReason = reason
			out[i].Explanation = explanation
			if fix != "" || out[i].FixSuggestion == "" {
				out[i].FixSuggestion = fix
			}
		}(i)
	}
	wg.Wait()
	return out
}

func triageFinding(ctx context.Context, client *ai.Client, f *core.Finding, explain bool) (verdict, confidence, reason, explanation, fix string) {
	var prompt string

	if f.Type == core.ScanTypeContainer {
		prompt = buildContainerPrompt(f, explain)
	} else if f.Type == core.ScanTypeSCA {
		prompt = buildSCAPrompt(f, explain)
	} else {
		var codeCtx string
		if f.Type == core.ScanTypeSecrets {
			codeCtx = fmt.Sprintf("detected value (redacted): %s", f.Redacted)
		} else {
			codeCtx = core.FileContext(f.FilePath, f.StartLine, 8)
		}
		prompt = buildSASTTriagePrompt(f, codeCtx, explain)
	}

	resp, err := client.Complete(ctx, prompt, 768)
	if err != nil {
		return "UNKNOWN", "", "AI triage failed: " + err.Error(), "", ""
	}

	return parseTriageResponse(resp)
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

Determine:
1. Is this a TRUE_POSITIVE (real risk in a running container) or FALSE_POSITIVE (package installed but vulnerability not exploitable in typical container usage)?
2. Your confidence in that verdict.
3. If TRUE_POSITIVE and no patch exists, suggest a concrete mitigation (e.g., use a newer base image, switch to a minimal/distroless image, pin a different package version, apply a config workaround). If a patch exists, state the upgrade command.

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

Determine:
1. Is this a TRUE_POSITIVE (real risk if the vulnerable function is called) or FALSE_POSITIVE (vulnerability is in an unused code path or test dependency)?
2. Your confidence in that verdict.
3. If TRUE_POSITIVE, provide the upgrade command or a workaround. If no patch exists, suggest alternatives (different package, version constraint, or mitigation).

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

func parseTriageResponse(resp string) (verdict, confidence, reason, explanation, fix string) {
	verdict = "UNKNOWN"
	var fixLines []string
	inFix := false

	for _, line := range strings.Split(resp, "\n") {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)

		if strings.HasPrefix(upper, "VERDICT:") {
			val := strings.TrimSpace(strings.TrimPrefix(upper, "VERDICT:"))
			if strings.Contains(val, "FALSE_POSITIVE") {
				verdict = "FALSE_POSITIVE"
			} else if strings.Contains(val, "TRUE_POSITIVE") {
				verdict = "TRUE_POSITIVE"
			}
			inFix = false
			continue
		}
		if strings.HasPrefix(upper, "CONFIDENCE:") {
			val := strings.TrimSpace(strings.TrimPrefix(upper, "CONFIDENCE:"))
			switch {
			case strings.Contains(val, "HIGH"):
				confidence = "HIGH"
			case strings.Contains(val, "MEDIUM"):
				confidence = "MEDIUM"
			case strings.Contains(val, "LOW"):
				confidence = "LOW"
			}
			inFix = false
			continue
		}
		if strings.HasPrefix(upper, "REASON:") {
			reason = strings.TrimSpace(trimmed[7:])
			inFix = false
			continue
		}
		if strings.HasPrefix(upper, "EXPLANATION:") {
			explanation = strings.TrimSpace(trimmed[12:])
			inFix = false
			continue
		}
		if strings.HasPrefix(upper, "FIX:") {
			rest := strings.TrimSpace(trimmed[4:])
			if rest != "" && strings.ToUpper(rest) != "N/A" && !isCodeFence(rest) {
				fixLines = append(fixLines, rest)
			}
			inFix = true
			continue
		}
		if inFix && trimmed != "" && strings.ToUpper(trimmed) != "N/A" && !isCodeFence(trimmed) {
			fixLines = append(fixLines, trimmed)
		}
	}

	fix = strings.Join(fixLines, "\n")
	return verdict, confidence, reason, explanation, fix
}

func isCodeFence(s string) bool {
	return strings.HasPrefix(s, "```")
}
