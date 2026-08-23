### Title
Unsanitized skill file/directory names allow ANSI/terminal escape injection into `gh skill install` output - ([File: pkg/cmd/skills/install/install.go])

### Finding Description
`installSkill` (`internal/skills/installer/installer.go:251-309`) writes each file from an attacker-controlled skill repository to disk. The destination path is validated only for path traversal via `safepaths.Absolute.Join` (`internal/safepaths/absolute.go:38-57`), which checks that the joined path stays under the base directory but performs no validation of the byte content of path components (no rejection of control characters, ANSI escape sequences, or embedded CR/LF). Git tree/blob paths returned by the GitHub API (`file.Path`) become `relPath` and are used verbatim as the on-disk file/directory name in `os.WriteFile(destPath, ...)` (`internal/skills/installer/installer.go:288-305`) and `installLocalSkill`'s `filepath.WalkDir`-based writes (`internal/skills/installer/installer.go:180-249`).

After installation, `runLocalInstall`/`runRemoteInstall` call `printFileTree` (`pkg/cmd/skills/install/install.go:1150-1161`), which calls `printTreeDir` (`pkg/cmd/skills/install/install.go:1163-1185`). `printTreeDir` reads the directory with `os.ReadDir` and writes `entry.Name()` directly via `fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), name)` with no escaping/sanitization of `name`. The output stream `w` is `opts.IO.ErrOut`, the same trusted stream used to print `"Installed %s (from %s) in %s\n"` success lines and the "Skills may contain prompt injections" warning immediately before/after the tree is rendered. `cs.Bold`/`cs.Muted` only wrap text with ANSI SGR codes for styling — they do not strip or escape attacker input.

Since filenames on Linux/macOS can contain arbitrary bytes other than `/` and NUL, an attacker-controlled repo can include a file or directory named e.g. `safe.txt\x1b[2K\rInstalled trusted-skill`. This name survives the traversal check (it does not touch `..`), gets written to disk unchanged, and is later echoed unsanitized into the terminal, allowing the attacker to forge cursor-movement/line-clear sequences that overwrite or fabricate lines of gh's own trusted "Installed" success message or hide subsequent warning text (e.g. the "Skills are not verified by GitHub..." disclaimer or "Review installed content before use" hint) from the user.

### Impact Explanation
This is an output/terminal spoofing issue: the victim's terminal can be made to display fabricated or altered gh status lines (e.g., hiding real filenames, or forging a fake "trusted" install message) after installing an attacker-supplied skill. It does not achieve code execution, credential theft, or file writes outside the intended directory — the underlying write is still confined by `safepaths`. Impact is limited to misleading CLI output that could reduce a user's suspicion of an otherwise-suspicious install, corresponding to a low/informational "spoofing of CLI output" class rather than a critical file-write or code-execution bug.

### Likelihood Explanation
Fully attacker-controlled and repeatable: any public GitHub repo used as a skill source can contain a file/directory whose git tree path embeds ANSI escape or CR sequences. No victim interaction beyond running `gh skill install <attacker-repo>` (or `gh skill preview`, which uses an analogous unsanitized `printTree` in `pkg/cmd/skills/preview/preview.go:541-557`) is required, and the same class of unsanitized name is displayed for both local and remote installs.

### Recommendation
Sanitize/escape entry names before printing them in `printTreeDir` (and the equivalent `printTree` in `preview.go`) — e.g., strip or visibly encode non-printable/control characters (such as with `strconv.Quote` for names containing control bytes, or replacing bytes < 0x20/0x7f with a placeholder) before writing to `w`. This should be applied generically to any user/attacker-controlled string interpolated into trusted CLI status output.

### Proof of Concept
```go
func TestPrintTreeDir_SanitizesControlCharacters(t *testing.T) {
    dir := t.TempDir()
    evilName := "safe.txt\x1b[2K\rInstalled trusted-skill"
    require.NoError(t, os.WriteFile(filepath.Join(dir, evilName), []byte("x"), 0o644))

    var buf bytes.Buffer
    io, _, _, _ := iostreams.Test()
    cs := io.ColorScheme()

    printTreeDir(&buf, cs, dir, "  ")

    out := buf.String()
    // Expect the raw ESC (0x1b) and CR (\r) control bytes to NOT appear verbatim,
    // proving the entry name was sanitized/escaped before being written to the
    // trusted output stream.
    assert.NotContains(t, out, "\x1b[2K")
    assert.NotContains(t, out, "\r")
}
```
Currently this test fails because `printTreeDir` (`pkg/cmd/skills/install/install.go:1177-1183`) writes `entry.Name()` unmodified, reproducing the escape-sequence injection described above.