package sast

import "fmt"

// codeFence is three backticks, used to build markdown code blocks.
const codeFence = "```"

// promptIntro is the intro section shared across all prompts (before the code block).
const promptIntro = `As a cybersecurity expert, analyze the following %s for security vulnerabilities. Only report findings if you have a high level of confidence the finding is exploitable. Do not make assumptions or infer anything that is not explicitly apparent in the code being reviewed.

File: %s
Language: %s

Code:
`

// promptResponseFormat is the response format shared across all prompts. The parser depends on this structure.
const promptResponseFormat = `
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

// promptCodeAnalysis is the guidance section for general source code analysis.
const promptCodeAnalysis = `

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
`

// promptDockerfile is the guidance section for Dockerfile and Containerfile analysis.
const promptDockerfile = `

## Dockerfile Security Analysis:

Analyze this Dockerfile for security misconfigurations and vulnerabilities. Check each of the following:

**1. PRIVILEGE ESCALATION:**
- Container runs as root (no USER directive, or USER set to root/0)
- Unnecessary capabilities or privilege grants
- SUID/SGID binaries installed and not cleaned up

**2. SECRET EXPOSURE:**
- Secrets, API keys, tokens, or passwords hardcoded in ENV or ARG instructions
- Secrets passed as build arguments (visible in image history via docker history)
- Credentials embedded in RUN commands (e.g., curl with auth headers, pip install with tokens in URLs)
- Secrets copied into the image that are not removed in the same layer

**3. BASE IMAGE RISKS:**
- Unpinned base image tags (using :latest or no tag instead of a digest or specific version)
- Base images from untrusted sources (not official or verified publisher)
- Using a full OS image when a minimal/distroless alternative exists

**4. DANGEROUS INSTRUCTIONS:**
- ADD used instead of COPY (ADD can fetch remote URLs and auto-extract archives)
- RUN commands that install packages without pinning versions
- RUN commands that pipe curl/wget output directly to sh/bash
- Package manager caches not cleaned in the same RUN layer

**5. MULTI-STAGE BUILD LEAKS:**
- Secrets, credentials, or build tools copied from builder stage to final stage
- Final stage inheriting unnecessary files or packages from build stages

**6. NETWORK AND RUNTIME:**
- Unnecessary ports exposed
- HEALTHCHECK missing (allows silent failures in orchestration)

## Severity Assessment:

**CRITICAL**: Running as root with exposed services, hardcoded production secrets
**HIGH**: Secrets in build args (visible in history), unpinned base images from untrusted sources, curl | sh patterns
**MEDIUM**: ADD instead of COPY, unpinned package versions, no USER directive, missing HEALTHCHECK
**LOW**: Package cache not cleaned, unnecessary packages installed, minor best practice violations
`

// promptCompose is the guidance section for Docker Compose file analysis.
const promptCompose = `

## Docker Compose Security Analysis:

Analyze this Docker Compose file for security misconfigurations and vulnerabilities. Check each of the following:

**1. CONTAINER ESCAPE / HOST ACCESS:**
- privileged: true (full host kernel access, container escape trivial)
- Docker socket mounted (/var/run/docker.sock) - grants full control over Docker daemon
- Host PID or network namespace (pid: host, network_mode: host)
- Capabilities added (cap_add: SYS_ADMIN, NET_ADMIN, etc.) without justification

**2. SECRET EXPOSURE:**
- Secrets, API keys, tokens, or passwords hardcoded in environment: blocks
- Credentials in command: or entrypoint: strings
- .env files referenced without noting they should be gitignored

**3. DANGEROUS VOLUME MOUNTS:**
- Sensitive host paths mounted: /etc, /root, /home, /var/run, /proc, /sys
- Writable mounts to host system directories
- Bind mounts without :ro (read-only) flag when write access is not needed

**4. NETWORK EXPOSURE:**
- Ports exposed to 0.0.0.0 (all interfaces) when localhost binding would suffice
- Database or internal service ports exposed to the host without justification
- Missing network isolation between services that don't need to communicate

**5. RESOURCE AND RUNTIME:**
- No resource limits (deploy.resources.limits) - allows DoS via resource exhaustion
- restart: always without health checks (restarts broken containers forever)
- Running containers as root (no user: directive)

## Severity Assessment:

**CRITICAL**: privileged: true, Docker socket mount, hardcoded production secrets
**HIGH**: Sensitive host path mounts (writable), host network/PID namespace, cap_add: SYS_ADMIN, database ports on 0.0.0.0
**MEDIUM**: Hardcoded non-production secrets, ports on 0.0.0.0, no resource limits, missing read-only flags on mounts
**LOW**: Missing health checks, minor network isolation gaps, .env files without gitignore note
`

// buildPrompt constructs the full security analysis prompt for a given file.
func buildPrompt(filePath, language, code string) string {
	var description string
	var analysis string

	switch language {
	case "dockerfile":
		description = "Dockerfile"
		analysis = promptDockerfile
	case "docker-compose":
		description = "Docker Compose file"
		analysis = promptCompose
	default:
		description = "source code"
		analysis = promptCodeAnalysis
	}

	return fmt.Sprintf(promptIntro, description, filePath, language) +
		codeFence + language + "\n" + code + "\n" + codeFence +
		analysis +
		promptResponseFormat
}
