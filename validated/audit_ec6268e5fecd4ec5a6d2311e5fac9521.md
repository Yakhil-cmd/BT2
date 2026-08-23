### Title
`iostreams.ContainsEscapeSequence` only detects ESC (0x1B) introducers, missing bare C1 control-code escape sequences - ([File: pkg/iostreams/content.go])

### Summary
`ContainsEscapeSequence` is implemented as a single-byte scan for `0x1B` (`bytes.IndexByte(b, 0x1B) >= 0`), which is used by `pkg/cmd/gist/view/view.go`'s raw, non-TTY output path to decide whether to refuse content or call `opts.IO.SetContentSanitization(false)` and print raw bytes. This check does not recognize 8-bit C1 control codes (e.g. `0x9B` CSI, `0x9D` OSC, `0x90` DCS) as escape sequences, even though many terminals accept these single-byte forms as equivalents of `ESC [`, `ESC ]`, `ESC P`.

### Finding Description
In `pkg/cmd/gist/view/view.go`, the raw-dump branch of `render()` guards untrusted gist content before writing it to a piped (non-TTY) stdout: [1](#0-0) 
It calls `iostreams.ContainsEscapeSequence(content.RawBytes())`, defined as: [2](#0-1) 
This is a raw search for the literal byte `0x1B`. It does not decode UTF-8, and it does not recognize the single-byte 8-bit C1 control code equivalents of ANSI escape introducers (`0x80`–`0x9F` range, e.g. `0x9B` = CSI, `0x9D` = OSC, `0x90` = DCS), which are valid terminal escape mechanisms recognized by xterm and many other terminal emulators when not strictly operating in UTF-8-only decode mode (and even in some UTF-8 terminals these bytes can still trigger control interpretation depending on implementation, or get passed through by naive downstream consumers that don't validate encoding). A gist file crafted with such bytes (e.g., `... 0x9B '3' '1' 'm' ...` as a CSI SGR sequence) would pass `ContainsEscapeSequence` as `false`, `SetContentSanitization(false)` would be invoked, and the raw bytes—including the functional escape sequence—would be written unsanitized to the piped, non-TTY output.

Only the existing unit test coverage exercises the classic `\x1b[31m` ESC-prefixed form: [3](#0-2) 
There is no test or code path that considers C1 8-bit forms, confirming this is a real detection gap rather than a covered/handled case.

### Impact Explanation
If a downstream consumer or terminal interprets the C1 byte forms as escape sequences (which is common/documented terminal behavior, e.g. xterm's 8-bit controls mode, and is the reason the OSC/CSI/DCS "C1" forms exist in ECMA-48 at all), an attacker-controlled gist can inject escape sequences into a victim's piped output despite `gh gist view <id> | some-consumer` running without `--allow-escape-sequences`. This falls under GitHub's "escape/terminal sequence injection into CLI output" impact class — the safeguard exists specifically to prevent this, and the detector has a bypassable blind spot.

### Likelihood Explanation
Preconditions: victim must pipe `gh gist view` output to a consumer that decodes/interprets 8-bit C1 control codes (not all terminals or all pipelines do this — many modern terminal emulators or tools operating strictly in UTF-8 mode will treat lone `0x9B` etc. as invalid UTF-8 and may replace or ignore it rather than execute it as CSI). This constrains real-world exploitability to specific terminal/consumer configurations (legacy terminals, terminals in 8-bit mode, or non-UTF8-aware readers), making this a genuine but environment-dependent bypass rather than a universal one.

### Recommendation
Broaden `ContainsEscapeSequence` to also detect bare C1 control bytes (`0x80`–`0x9F`) as potential escape introducers, or explicitly document/reject the possibility by normalizing/validating content as strict UTF-8 first (rejecting invalid byte sequences, since valid UTF-8 text cannot contain a raw C1 byte as a standalone codepoint under NFC use) before the ESC-only scan.

### Proof of Concept
```go
func TestContainsEscapeSequence_C1Bypass(t *testing.T) {
    // 0x9B is the single-byte C1 equivalent of ESC [ (CSI), recognized by
    // many terminals (e.g. xterm 8-bit control mode) as starting an SGR
    // sequence "CSI 31 m" (set red foreground), functionally identical to
    // "\x1b[31m".
    payload := []byte("danger\x9b" + "31m" + "text")
    assert.True(t, ContainsEscapeSequence(payload), "C1 CSI form should be detected but is not")
}
```
Expected today: the assertion fails, demonstrating the detector misses the C1 form and allows `viewRun`'s raw path to call `SetContentSanitization(false)` and print the sequence unsanitized to a piped stdout. A fuzz corpus should additionally include `0x90` (DCS), `0x9D` (OSC), and `0x9E`/`0x9F` (PM/APC) C1 introducers.

### Citations

**File:** pkg/cmd/gist/view/view.go (L183-196)
```go
		// Raw dump. On a terminal, ContentOut renders escape sequences inert.
		// When the output is piped, refuse content carrying escape sequences
		// rather than silently rewriting the bytes; --allow-escape-sequences
		// forces raw.
		if !opts.AllowEscapeSequences && !opts.IO.IsStdoutTTY() {
			if iostreams.ContainsEscapeSequence(content.RawBytes()) {
				return errors.New("gist file contains terminal escape sequences; pass --allow-escape-sequences to view it anyway")
			}
			opts.IO.SetContentSanitization(false)
		}
		raw := content.Raw()
		if _, err := fmt.Fprint(opts.IO.ContentOut, raw); err != nil {
			return err
		}
```

**File:** pkg/iostreams/content.go (L16-20)
```go
// ContainsEscapeSequence reports whether b contains an ANSI escape byte (0x1B),
// which can manipulate a terminal when printed.
func ContainsEscapeSequence(b []byte) bool {
	return bytes.IndexByte(b, 0x1B) >= 0
}
```

**File:** pkg/iostreams/content_test.go (L48-51)
```go
func TestContainsEscapeSequence(t *testing.T) {
	assert.False(t, ContainsEscapeSequence([]byte("plain text")))
	assert.True(t, ContainsEscapeSequence([]byte("danger\x1b[31m")))
}
```
