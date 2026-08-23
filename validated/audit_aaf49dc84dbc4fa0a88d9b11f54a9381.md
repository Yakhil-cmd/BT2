### Title
Unbounded in-memory buffering of textual response bodies in `CopyGuardedContent` enables memory/CPU amplification - (File: pkg/iostreams/content.go)

### Summary
`CopyGuardedContent` reads the first 512 bytes to classify content as binary or text via `BinaryContentType`, but for anything classified as text it calls `io.ReadAll(r)` to buffer the *entire remaining body* into memory before scanning it with `ContainsEscapeSequence`. An attacker who controls a response body (e.g., an API response fetched by `gh api`, or gist raw content) can make the first 512 bytes clean ASCII/text and place arbitrarily large filler content afterward, forcing the client to fully buffer that payload in memory regardless of size.

### Finding Description
In `pkg/iostreams/content.go`:
- `CopyGuardedContent` (lines 63-92) reads a 512-byte sniff head with `io.ReadFull`, then classifies it with `BinaryContentType` (line 71).
- If the sniff is not classified as binary (i.e., `http.DetectContentType` on the first 512 bytes returns a `text/*` MIME type), execution falls to line 82: `rest, err := io.ReadAll(r)`, which reads all remaining bytes from the reader into memory with no size cap, `LimitReader`, or `http.MaxBytesReader` anywhere in the call chain (confirmed no such guards exist in the repo).
- The concatenated `content` (line 86) is only then scanned for the 0x1B escape byte via `ContainsEscapeSequence`.
- Because the classification only inspects the first 512 bytes, an attacker fully controls whether the "text" path (unbounded buffering) or "binary" path (streamed via `io.Copy`, not buffered) is taken. By keeping the leading 512 bytes as plain ASCII and appending gigabytes of filler afterward (with or without a trailing escape byte), the attacker forces full-body buffering before any output or rejection occurs.
- This code path is reachable from `gh api` (`pkg/cmd/api/api.go`, which calls `CopyGuardedContent`) when a `gh api` command is pointed at an attacker-influenced path/host returning attacker-controlled response bodies, and potentially other callers such as `pkg/cmd/release/download/download.go`.

No existing safeguard (size limit, streaming scan, or bounded body reader) mitigates this; the guard exists purely to detect terminal escape sequences and binary content types, not to bound memory usage.

### Impact Explanation
This is a denial-of-service / resource-amplification issue on the victim's machine: a single attacker-controlled HTTP response can force `gh` to allocate memory proportional to the full response size (potentially very large, e.g., hundreds of MB to GB) before any streaming or rejection occurs, which can exhaust memory or cause significant CPU/GC pressure. It does not by itself grant code execution, credential exfiltration, file write outside intended paths, or authorization bypass — it is a resource-exhaustion / availability impact rather than a confidentiality/integrity/execution compromise, and there is no application-level size limit already violated (HTTP responses of large size are otherwise expected to be streamed, but here they're needlessly buffered).

### Likelihood Explanation
Feasible and repeatable: any attacker who can influence what `gh api <path>` fetches (a malicious/compromised host the victim points `gh api --hostname` at, or a large attacker-controlled response body from a legitimate-looking endpoint) can trigger it. Preconditions require the victim to run `gh api` (or another `CopyGuardedContent` consumer) against attacker-controlled content and pipe/consume output where `isTTY` is false or true — the buffering happens before the TTY check for the text branch, so it happens in both cases. Repeatability is high since it requires no special timing or race condition, just a large clean-ASCII payload.

### Recommendation
Bound the amount of data read before/while classifying as text, e.g., use `io.LimitReader` or `http.MaxBytesReader`-style limits for the full body, or perform the escape-sequence scan incrementally via a streaming scanner (buffer in fixed-size chunks, checking each chunk for 0x1B, writing already-scanned chunks progressively or buffering only up to a configurable maximum before falling back to a streaming write with a warning). At minimum, add a maximum buffer size constant and return an error (or fall back to streaming with escape-stripping) once exceeded, rather than calling unbounded `io.ReadAll`.

### Proof of Concept
```go
func TestCopyGuardedContent_LargeTextBufferedFully(t *testing.T) {
    // 512 bytes of clean ASCII head + 200MB of filler text, no escape byte anywhere,
    // or escape byte placed only at the very end.
    head := bytes.Repeat([]byte("a"), 512)
    filler := bytes.Repeat([]byte("b"), 200*1024*1024)
    body := append(append([]byte{}, head...), filler...)

    r := bytes.NewReader(body)
    var buf bytes.Buffer

    var memBefore, memAfter runtime.MemStats
    runtime.ReadMemStats(&memBefore)

    err := iostreams.CopyGuardedContent(&buf, r, false)

    runtime.ReadMemStats(&memAfter)

    require.NoError(t, err)
    // Assert that memory allocated during the call is on the order of the full body size,
    // demonstrating io.ReadAll buffered the entire ~200MB payload instead of streaming it.
    require.Greater(t, memAfter.TotalAlloc-memBefore.TotalAlloc, uint64(150*1024*1024))
}
```
Expected assertion: allocation delta scales linearly with attacker-supplied filler size, confirming unbounded buffering via `io.ReadAll` at `pkg/iostreams/content.go:82` regardless of payload size, before the `ContainsEscapeSequence` check at line 87 ever runs.