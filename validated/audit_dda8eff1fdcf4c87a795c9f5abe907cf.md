### Title
Tool-call argument fields (e.g. `runSetupToolArgs.Name`, `bashToolArgs.Description`, `reportProgressToolArgs.CommitMessage`) bypass ANSI sanitization and are printed raw to the terminal, enabling escape-sequence/title-spoofing injection - ([File: pkg/cmd/agent-task/shared/log.go])

### Summary
`renderLogEntry` unmarshals attacker-influenced `tc.Function.Arguments` into plain `string` fields (e.g. `runSetupToolArgs.Name`) via the generic `unmarshal[T]` helper, then passes them directly to `fmt.Fprintf` in `renderToolCallTitle` without any ANSI/OSC sanitization. This is inconsistent with the rest of the file, which explicitly wraps other untrusted streamed fields (`Delta.Content`, `Delta.ReasoningText`) in `iostreams.Untrusted` specifically to auto-strip escape sequences on print.

### Finding Description
`chatCompletionChunkEntry` (log.go:496-518) decodes `tool_calls[].function.arguments` as a raw JSON string, `tc.Function.Arguments` [1](#0-0) . In `renderLogEntry`, the `run_setup` case does:

```go
if v := unmarshal[runSetupToolArgs](args); v != nil {
    renderToolCallTitle(w, cs, v.Name, "")
    continue
}
``` [2](#0-1) 

`runSetupToolArgs.Name` is declared as a plain `string` [3](#0-2) , unlike `Delta.Content`/`Delta.ReasoningText`, which are typed `iostreams.Untrusted` precisely so that `fmt` printing auto-sanitizes ANSI/OSC control sequences via `Untrusted.String()` [4](#0-3) .

`renderToolCallTitle` writes `toolName` (here, the attacker-influenced `v.Name`) directly with `fmt.Fprintf(w, "%s\n", toolName)` with no sanitization step at all — `cs.Bold` is only applied to the `title` parameter, not `toolName`, and even `cs.Bold` merely wraps a string in ANSI bold codes without stripping embedded escapes from the content [5](#0-4) . The same pattern of raw, unsanitized `string` fields flowing into `renderToolCallTitle`/`cs.Bold` also affects `bashToolArgs.Description` (line 151), `reportProgressToolArgs.CommitMessage` (line 215), and file paths via `relativeFilePath` for `create`/`str_replace`/`view` (lines 140, 236, 249).

Note that the generic `unmarshal[T]` helper's error-swallowing (returning `nil` on `json.Unmarshal` failure, log.go:403-409) does not itself cause the vulnerability — malformed JSON simply causes the branch to be skipped. The actual root cause is that *successfully parsed, valid* JSON string content in these fields is never routed through `iostreams.Untrusted` before being written to the terminal, unlike sibling fields in the same struct that the codebase authors deliberately protected.

An attacker who can influence the coding-agent's tool-call `arguments` (e.g., via prompt injection embedded in an issue/PR/repo content that the agent processes, later surfaced through the session-log API and rendered locally by `gh agent-task view --log` or similar) can set `name` to a string containing raw ESC (0x1b) bytes, e.g. an OSC 0/2 terminal-title sequence (`\x1b]0;spoofed-title\x07`) or other CSI sequences, and have them emitted verbatim to the victim's terminal.

### Impact Explanation
This enables terminal escape-sequence injection: OSC sequences can spoof the terminal window/tab title (phishing vector) or manipulate cursor/screen state (e.g., hide/overwrite legitimate output) when the victim runs `gh` to view agent-task logs. This maps to the "terminal escape sequence / output injection" class of GitHub bounty impacts — a UI-spoofing/social-engineering-enabling issue rather than direct code execution or credential theft.

### Likelihood Explanation
Requires the attacker to control content that ends up in the tool-call arguments recorded in a Copilot coding-agent session's chat-completion-chunk log (e.g. via prompt injection against the agent, since the agent's own tool invocations are logged and later fetched/rendered by `gh`). This is plausible but indirect — it depends on the agent actually echoing attacker-supplied text into a tool-call argument such as `name`, `description`, or `commitMessage`, and the victim then viewing those logs locally with `gh`.

### Recommendation
Type all string fields in tool-call argument structs that originate from `tc.Function.Arguments` (e.g. `runSetupToolArgs.Name`, `bashToolArgs.Description`, `reportProgressToolArgs.CommitMessage`, `viewToolArgs.Path`, `createToolArgs.Path`/`FileText`, `strReplaceToolArgs.Path`) as `iostreams.Untrusted` (or explicitly sanitize with the same `asciisanitizer`/`stripControl` logic) before passing them to `renderToolCallTitle`, `cs.Bold`, or any other terminal-writing call, matching the protection already applied to `Delta.Content`/`Delta.ReasoningText`.

### Proof of Concept
Fuzz/unit test plan:
```go
func TestRenderToolCallTitle_EscapeInjection(t *testing.T) {
    io, _, out, _ := iostreams.Test()
    cs := io.ColorScheme()
    var buf bytes.Buffer
    maliciousName := "\x1b]0;pwned-title\x07Run Setup"
    renderToolCallTitle(&buf, cs, maliciousName, "")
    if bytes.ContainsRune(buf.Bytes(), 0x1b) {
        t.Fatalf("raw ESC byte reached terminal writer: %q", buf.String())
    }
    _ = out
}
```
Expected (current) result: the assertion fails — the raw `0x1b` byte from `maliciousName` is present in `buf`, confirming the field is not sanitized. A companion end-to-end test can feed a `chat.completion.chunk` JSON payload with `tool_calls[0].function.name == "run_setup"` and `arguments == "{\"name\":\"\u001b]0;pwned\u0007\"}"` through `Render` and assert the writer output contains no raw ESC byte.

### Citations

**File:** pkg/cmd/agent-task/shared/log.go (L129-133)
```go
			case "run_setup":
				if v := unmarshal[runSetupToolArgs](args); v != nil {
					renderToolCallTitle(w, cs, v.Name, "")
					continue
				}
```

**File:** pkg/cmd/agent-task/shared/log.go (L413-429)
```go
func renderToolCallTitle(w io.Writer, cs *iostreams.ColorScheme, toolName, title string) {
	// Should not happen, but if it does we still want to print a heading
	// with the information we do have.
	if toolName == "" {
		toolName = "Generic tool call"
	}

	if title != "" {
		title = cs.Bold(title)
	}

	if title != "" {
		fmt.Fprintf(w, "%s: %s\n", toolName, title)
	} else {
		fmt.Fprintf(w, "%s\n", toolName)
	}
}
```

**File:** pkg/cmd/agent-task/shared/log.go (L506-513)
```go
			ToolCalls     []struct {
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
				Index int    `json:"index"`
				ID    string `json:"id"`
			} `json:"tool_calls"`
```

**File:** pkg/cmd/agent-task/shared/log.go (L520-522)
```go
type runSetupToolArgs struct {
	Name string `json:"name"`
}
```

**File:** pkg/iostreams/untrusted.go (L35-44)
```go
// String returns the content with ANSI escape sequences neutralized. It is
// called automatically by the fmt package, so printing an Untrusted value is
// safe by default on every fmt path.
func (u Untrusted) String() string {
	sanitized, _, err := transform.String(&asciisanitizer.Sanitizer{}, u.raw)
	if err != nil {
		return stripControl(u.raw)
	}
	return sanitized
}
```
