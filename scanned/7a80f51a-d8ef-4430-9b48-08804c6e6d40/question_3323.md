# Q3323: external-file-url via if 3323

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `if` (packages/gui/src/util/parseFileContent.ts) control iframe content with navigation or message attempts with precision-boundary values and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/util/parseFileContent.ts` / `if`
- Entrypoint: embedded iframe render path
- Attacker controls: iframe content with navigation or message attempts; with precision-boundary values
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
