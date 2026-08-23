### Title
Terminal escape sequence injection via unsanitized attestation Subject.Name/Digest in `printVerifiedSubjects` - ([File: pkg/cmd/release/verify/verify.go])

### Finding Description
`verifyRun` fetches a release attestation from the GitHub API and passes it to `printVerifiedSubjects` (pkg/cmd/release/verify/verify.go:196-238), which unmarshals the DSSE payload into an in-toto `v1.Statement` and iterates `statementData.Subject`, writing `s.Name` and the digest map values directly via `table.AddField(name)` / `table.AddField(digestStr)` before calling `table.Render()`, which writes to `io.Out` [1](#0-0) . Neither this function nor the wrapping `tableprinter.New`/`AddField` call path in this repo (internal/tableprinter/table_printer.go) performs any stripping or escaping of ANSI/control characters before writing field content — the wrapper only adds header casing/padding/color logic and delegates row rendering to the external `github.com/cli/go-gh/v2/pkg/tableprinter` package [2](#0-1) . The `Subject.Name` and digest fields originate from the attestation predicate/subject content returned by `GetByDigest`/the DSSE envelope, which is attacker-influenced content associated with a release built by the repo owner (an unprivileged actor can publish a release/attestation in their own repo that a victim then runs `gh release verify` against). If the underlying rendering library does not itself strip control sequences, embedding raw ANSI escapes (e.g., `\x1b[`) in `Subject.Name` would be written unsanitized to the victim's terminal, potentially clearing the screen, repositioning the cursor to hide/forge output, or (with terminal emulators supporting OSC/DECRQSS features) attempting more exotic terminal manipulation.

### Impact Explanation
If exploitable, this would allow an attacker who controls a release's attestation subject content to forge terminal output or hide parts of the `gh release verify` output from the victim (output spoofing / terminal UI manipulation), which maps to a low-severity "output injection" class rather than code execution or credential theft, since no shell/command execution, credential exfiltration, or file write is achieved directly.

### Likelihood Explanation
I was not able to confirm within this repo whether the actual sanitization occurs inside the external dependency `github.com/cli/go-gh/v2/pkg/tableprinter` (vendored outside this codebase and not indexed here). The wrapper code in this repository (`internal/tableprinter/table_printer.go`) adds no escaping itself, so if the upstream `go-gh` `tableprinter.AddField`/`Render` does not sanitize control characters, the path is reachable with attacker-controlled input and would be trivially reproducible; if `go-gh`'s tableprinter already strips/escapes non-printable/control characters (common for TTY-safe renderers), this path is not exploitable and the issue reduces to a dependency-behavior question, which per the rules should not be treated as a standalone finding.

### Recommendation
Explicitly sanitize `Subject.Name` and digest values before calling `table.AddField`, e.g., by stripping ASCII control characters (0x00–0x1F, 0x7F) and disallowing multi-byte terminal escape sequences, regardless of what the underlying `go-gh` tableprinter does, to guarantee output safety at the call site in `printVerifiedSubjects`.

### Proof of Concept
Add a Go test in `pkg/cmd/release/verify/verify_test.go` that constructs a `verification.AttestationProcessingResult` whose DSSE envelope payload contains a `Subject` with `Name` set to a string containing `"\x1b[2J\x1b[H"` (clear-screen + cursor-home) and a benign digest, call `printVerifiedSubjects(io, result)` with an `iostreams.Test()` IO, then assert that the raw bytes `\x1b[` do NOT appear unescaped in the captured `io.Out` buffer (or that they are replaced with a printable placeholder). Currently, based on code review, no stripping call exists at this call site — the actual pass/fail of this test depends on `go-gh`'s tableprinter internals, which could not be verified from this repository's indexed contents; running the test against the real dependency is required to confirm exploitability.

### Citations

**File:** pkg/cmd/release/verify/verify.go (L216-230)
```go
	for _, s := range statementData.Subject {
		name := s.Name
		digest := s.Digest

		if name != "" {
			digestStr := ""
			for key, value := range digest {
				digestStr = key + ":" + value
			}

			table.AddField(name)
			table.AddField(digestStr)
			table.EndRow()
		}
	}
```

**File:** internal/tableprinter/table_printer.go (L36-88)
```go
var (
	WithColor    = tableprinter.WithColor
	WithPadding  = tableprinter.WithPadding
	WithTruncate = tableprinter.WithTruncate
)

type headerOption struct {
	columns []string
}

// New creates a TablePrinter from an IOStreams.
func New(ios *iostreams.IOStreams, headers headerOption) *TablePrinter {
	maxWidth := 80
	isTTY := ios.IsStdoutTTY()
	if isTTY {
		maxWidth = ios.TerminalWidth()
	}

	return NewWithWriter(ios.Out, isTTY, maxWidth, ios.ColorScheme(), headers)
}

// NewWithWriter creates a TablePrinter from a Writer, whether the output is a terminal, the terminal width, and more.
func NewWithWriter(w io.Writer, isTTY bool, maxWidth int, cs *iostreams.ColorScheme, headers headerOption) *TablePrinter {
	tp := &TablePrinter{
		TablePrinter: tableprinter.New(w, isTTY, maxWidth),
		isTTY:        isTTY,
		cs:           cs,
	}

	if isTTY && len(headers.columns) > 0 {
		// Make sure all headers are uppercase, taking a copy of the headers to avoid modifying the original slice.
		upperCasedHeaders := make([]string, len(headers.columns))
		for i := range headers.columns {
			upperCasedHeaders[i] = strings.ToUpper(headers.columns[i])
		}

		// Make sure all header columns are padded - even the last one. Previously, the last header column
		// was not padded. In tests cs.Enabled() is false which allows us to avoid having to fix up
		// numerous tests that verify header padding.
		var paddingFunc func(int, string) string
		if cs.Enabled {
			paddingFunc = text.PadRight
		}

		tp.AddHeader(
			upperCasedHeaders,
			WithPadding(paddingFunc),
			WithColor(cs.TableHeader),
		)
	}

	return tp
}
```
