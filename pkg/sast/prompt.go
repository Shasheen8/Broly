package sast

import "fmt"

// codeFence is three backticks, used to build markdown code blocks.
const codeFence = "```"

// promptPart1 is the intro section of the security analysis prompt (before the code block).
const promptPart1 = `As a cybersecurity expert, analyze the following source code for security vulnerabilities. Only report findings if you have a high level of confidence the finding is exploitable. Do not make assumptions or infer anything that is not explicitly apparent in the code being reviewed.

File: %s
Language: %s

Code:
`

// promptPart2 is the guidance section (after the code block).
const promptPart2 = `

## Data Flow Analysis Requirements:

**1. SOURCE IDENTIFICATION**: Identify all user-controllable inputs in this file:
- Function parameters from external calls
- Command-line arguments
- HTTP request data (headers, query params, body)
- File contents read from user-specified paths
- Database query results from user input
- Variables or inputs sourced from CI/CD variables or other configuration files are considered secure. Focus on user-provided inputs.

**2. SINK IDENTIFICATION**: Identify dangerous operations that could be exploited:
- Network requests
- URL construction functions
- Path resolution and file system operations
- Database queries
- OS command execution
- Deserialization operations
- Template rendering with user input

**3. CROSS-FILE FLOW TRACING**: For each potential vulnerability:
- **Entry Point**: Where does untrusted data enter the system?
- **Flow Path**: Trace the data through function calls, imports, and exports
- **Intermediate Processing**: What validation/sanitization occurs along the path?
- **Exploitation Point**: Where does the untrusted data reach a dangerous sink?

**4. MULTI-FILE CONTEXT**: When analyzing imports/exports/function calls:
- Identify which imported functions likely receive the traced data
- Specify which additional files would need to be analyzed to confirm exploitability

## Severity Assessment Guidelines:

**CRITICAL/HIGH severity is appropriate when:**
- The vulnerability is exploitable by an unauthenticated external attacker
- The vulnerability requires minimal or no privileges
- User input is directly controllable through normal application interfaces

**MEDIUM severity is appropriate when:**
- The vulnerability requires authenticated access but not elevated privileges
- The attack surface is moderately restricted

**LOW severity is appropriate when:**
- The attacker must have privileged/administrative access to the system (e.g., ability to trigger jobs, modify parameters, access admin panels)
- The attacker must control environment variables or deployment configuration
- The vulnerability exists in internal tools or scripts that require elevated permissions to execute

**Key principle**: If successful exploitation requires the attacker to already have significant access to the system (admin privileges, infrastructure access), the severity should be LOW or MEDIUM, not CRITICAL or HIGH.

## Response Format:

If no vulnerabilities are found, respond with exactly: NO_FINDINGS

Otherwise, for each finding use this exact format (separate multiple findings with a blank line):

- **Vulnerability Level**: [CRITICAL/HIGH/MEDIUM/LOW/INFO]
- **Issue**: Brief description of the vulnerability.
- **Location**: File name and line number(s) where the vulnerability exists. If not applicable, use "N/A".
- **CVSS Vector**: The full CVSS v3.1 vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"). Ensure the Privileges Required (PR) metric accurately reflects the access level needed for exploitation.
- **Risk**: A brief explanation of the security impact, including specific mention of the attack prerequisites.
- **Fix**: Specific remediation steps, including a secure code example.

---

Rules:
- Do not infer missing context; only report what is explicitly visible in the code.
- Focus on vulnerabilities that are proven to be exploitable based on the code provided.
- Only report findings with high confidence.
- Do not report informational style warnings or best practices that are not actual vulnerabilities.`

// buildPrompt constructs the full security analysis prompt for a given file.
func buildPrompt(filePath, language, code string) string {
	return fmt.Sprintf(promptPart1, filePath, language) +
		codeFence + language + "\n" + code + "\n" + codeFence +
		promptPart2
}
