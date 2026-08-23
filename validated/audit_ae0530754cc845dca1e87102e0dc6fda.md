Confirmed: `session.Error.Message` is written raw to `opts.IO.Out` via `fmt.Fprintf` in `printSession` with no sanitization of control characters.

### Title
Unsanitized server-controlled `SessionError.Message`/session fields written to terminal enable ANSI/OSC-8 escape injection - ([File: pkg/cmd/agent-task/view/view.go])

### Summary
`printSession` in `pkg/cmd/agent-task/view/view.go` writes `session.Error.Message` (and `session.Name`, PR title, etc.) directly to `opts.IO.Out` via `fmt.Fprintf` without any stripping of ANSI/OSC control sequences. These fields originate from the CAPI `/agents/sessions/{id}` JSON response, decoded verbatim in `pkg/cmd/agent-task/capi/sessions.go`'s `session` struct and passed through unmodified by `fromAPISession`.

### Finding Description
The call chain is: `CAPIClient.GetSession` ( [1](#0-0) ) decodes the raw JSON `session` struct including `Error.Message`, `Name`, `EventURL`, and `Logs` fields with no sanitization, then `fromAPISession` copies `Error.Message` and other fields straight into the `Session`/`SessionError` structs used for display ( [2](#0-1) ). In `view.go`, `printSession` prints `session.Name`, `session.Error.Message`, and other fields directly via `fmt.Fprintf(opts.IO.Out, ...)` ( [3](#0-2) ), including the specific line `message := session.Error.Message; ...; fmt.Fprintf(opts.IO.Out, "\n%s %s\n", cs.FailureIconWithColor(cs.Red), message)` ( [4](#0-3) ). No ANSI-stripping, control-character filtering, or hyperlink escaping is applied anywhere in this path — `grep` for ansi/strip/OSC sanitization logic in `pkg/cmd/agent-task/**` returned no results, and the `iostreams` package's color-scheme helpers (`cs.FailureIconWithColor`, `cs.Muted`, `cs.Bold`) only add color codes, they do not sanitize input text for embedded escapes.

An attacker who can cause the agent-task session to end up with an attacker-controlled `error.message` (e.g., via a custom/malicious agent whose task fails with an error string it controls, which the CAPI service then stores and returns as-is) can embed raw ANSI escape sequences or OSC 8 hyperlink sequences in that string. When the victim later runs `gh agent-task view` on that session, the terminal renders these sequences directly, which can spoof gh's trusted output (e.g., fake success/failure banners, fake prompts) or render deceptive/hidden hyperlinks.

### Impact Explanation
This maps to terminal output spoofing / UI redress via escape sequence injection — an attacker-controlled string reaches the terminal unsanitized, enabling cursor movement, text overwrite, color manipulation, or clickable OSC 8 hyperlinks with a mismatched display/target that could be leveraged for phishing (e.g., a link that displays as `https://github.com/...` but points elsewhere) or content spoofing to make a compromised/failed session look benign. This does not achieve direct code execution or credential exfiltration on its own, but it is a legitimate CLI output-integrity issue matching GitHub's "terminal escape sequence injection" bounty class.

### Likelihood Explanation
Feasibility depends on whether an unprivileged attacker can actually get an arbitrary string into `session.Error.Message` (or `Name`) as stored by the CAPI backend for a session the victim will view — this requires triggering an agent-task session (e.g., via a custom/malicious Copilot agent responding to a PR/issue the attacker controls) whose failure message the attacker can set to arbitrary text. This precondition is plausible per the prompt's threat model but its exact feasibility depends on the CAPI backend's validation of agent-provided error messages, which is outside this repository's code and not verifiable from the client alone. Given the precondition is met, the injection into the victim's terminal is fully reproducible and deterministic — every field printed by `printSession` (Name, Error.Message, EventURL-derived text, etc.) follows the same unsanitized path.

### Recommendation
Sanitize/strip ANSI escape and control sequences from all server-controlled string fields (`session.Name`, `session.Error.Message`, `session.EventURL`-derived text, log content) before writing them to `opts.IO.Out`/`opts.IO.ErrOut`, e.g., using the same sanitization utilities gh already uses elsewhere for untrusted text output (if any exist in `pkg/text` or `pkg/iostreams`), or add a dedicated `text.SanitizeControlSequences`-style helper applied in `printSession` and `printLogs` before printing untrusted fields.

### Proof of Concept
```go
// pkg/cmd/agent-task/view/view_test.go (new test)
func TestPrintSession_SanitizesErrorMessage(t *testing.T) {
    ios, _, out, _ := iostreams.Test()
    session := &capi.Session{
        Name:  "task",
        State: "failed",
        Error: &capi.SessionError{
            Message: "\x1b[2J\x1b[H\x1b]8;;https://evil.example/phish\x07Click here for details\x1b]8;;\x07",
        },
    }
    opts := &ViewOptions{IO: ios}
    printSession(opts, session)

    // Expect no raw ESC (0x1b) bytes in output; only sanitized/escaped text.
    require.NotContains(t, out.String(), "\x1b")
}
```
Run against current code: the test fails because the raw `\x1b` sequences pass through unmodified into `out.String()`, confirming the injection reaches the IOStreams writer unsanitized.

### Citations

**File:** pkg/cmd/agent-task/capi/sessions.go (L296-336)
```go
// GetSession retrieves a specific agent session by ID.
func (c *CAPIClient) GetSession(ctx context.Context, id string) (*Session, error) {
	if id == "" {
		return nil, fmt.Errorf("missing session ID")
	}

	u, err := safeurl.JoinPathWithHostPrefix(c.capiBaseURL, "agents", "sessions", id)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusNotFound {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session: %s", res.Status)
	}

	var rawSession session
	if err := json.NewDecoder(res.Body).Decode(&rawSession); err != nil {
		return nil, fmt.Errorf("failed to decode session response: %w", err)
	}

	sessions, err := c.hydrateSessionPullRequestsAndUsers([]session{rawSession})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch session resources: %w", err)
	}

	return sessions[0], nil
}
```

**File:** pkg/cmd/agent-task/capi/sessions.go (L583-610)
```go
func fromAPISession(s session) *Session {
	result := Session{
		ID:              s.ID,
		Name:            s.Name,
		UserID:          s.UserID,
		AgentID:         s.AgentID,
		Logs:            s.Logs,
		State:           s.State,
		OwnerID:         s.OwnerID,
		RepoID:          s.RepoID,
		ResourceType:    s.ResourceType,
		ResourceID:      s.ResourceID,
		LastUpdatedAt:   s.LastUpdatedAt,
		CreatedAt:       s.CreatedAt,
		CompletedAt:     s.CompletedAt,
		EventURL:        s.EventURL,
		EventType:       s.EventType,
		PremiumRequests: s.PremiumRequests,
		WorkflowRunID:   s.WorkflowRunID,
	}
	if s.Error != nil {
		result.Error = &SessionError{
			Code:    s.Error.Code,
			Message: s.Error.Message,
		}
	}
	return &result
}
```

**File:** pkg/cmd/agent-task/view/view.go (L303-367)
```go
func printSession(opts *ViewOptions, session *capi.Session) {
	cs := opts.IO.ColorScheme()

	fmt.Fprintf(opts.IO.Out, "%s • %s\n",
		shared.ColorFuncForSessionState(*session, cs)(shared.SessionStateString(session.State)),
		cs.Bold(session.Name),
	)

	if session.User != nil {
		fmt.Fprintf(opts.IO.Out, "Started on behalf of %s %s\n", session.User.Login, text.FuzzyAgo(time.Now(), session.CreatedAt))
	} else {
		// Should never happen, but we need to cover the path
		fmt.Fprintf(opts.IO.Out, "Started %s\n", text.FuzzyAgo(time.Now(), session.CreatedAt))
	}

	usedPremiumRequests := strings.TrimSuffix(fmt.Sprintf("%.1f", session.PremiumRequests), ".0")
	usedPremiumRequestsNote := fmt.Sprintf("Used %s premium request(s)", usedPremiumRequests)

	var durationNote string
	if session.CompletedAt.After(session.CreatedAt) {
		durationNote = fmt.Sprintf(" • Duration %s", session.CompletedAt.Sub(session.CreatedAt).Round(time.Second).String())
	}

	fmt.Fprintf(opts.IO.Out, "%s%s\n", cs.Muted(usedPremiumRequestsNote), cs.Muted(durationNote))

	// Note that when the session is just created, a PR is not yet available for it.
	if session.PullRequest != nil {
		fmt.Fprintf(opts.IO.Out, "\n%s%s • %s\n",
			session.PullRequest.Repository.NameWithOwner,
			cs.ColorFromString(prShared.ColorForPRState(*session.PullRequest))(fmt.Sprintf("#%d", session.PullRequest.Number)),
			cs.Bold(session.PullRequest.Title),
		)
	}

	if session.Error != nil {
		var workflowRunURL string
		if session.WorkflowRunID != 0 && session.PullRequest != nil {
			if u, err := url.Parse(session.PullRequest.URL); err == nil {
				workflowRunURL = fmt.Sprintf("%s://%s/%s/actions/runs/%d", u.Scheme, u.Host, session.PullRequest.Repository.NameWithOwner, session.WorkflowRunID)
			}
		}

		message := session.Error.Message
		if message == "" {
			message = "An error occurred"
		}
		fmt.Fprintf(opts.IO.Out, "\n%s %s\n", cs.FailureIconWithColor(cs.Red), message)

		if workflowRunURL != "" {
			// We don't need to prefix the link with any text (e.g. "checkout the logs here")
			// because the error message already contains all the information.
			fmt.Fprintf(opts.IO.Out, "%s\n", workflowRunURL)
		}
	}

	if !opts.Log {
		fmt.Fprint(opts.IO.Out, cs.Mutedf("\nFor detailed session logs, try:\ngh agent-task view '%s' --log\n", session.ID))
	} else if !opts.Follow {
		fmt.Fprint(opts.IO.Out, cs.Mutedf("\nTo follow session logs, try:\ngh agent-task view '%s' --log --follow\n", session.ID))
	}

	if session.PullRequest != nil {
		fmt.Fprintln(opts.IO.Out, cs.Muted("\nView this session on GitHub:"))
		fmt.Fprintln(opts.IO.Out, cs.Muted(fmt.Sprintf("%s/agent-sessions/%s", session.PullRequest.URL, url.PathEscape(session.ID))))
	}
```
