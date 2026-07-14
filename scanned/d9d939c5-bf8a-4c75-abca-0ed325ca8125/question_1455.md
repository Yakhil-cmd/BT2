# Q1455: external-file-url via if 1455

## Question
Can an unprivileged attacker entering through the external link click in `if` (packages/gui/src/util/parseFileContent.ts) control filename/path with traversal or extension mismatch after a failed RPC response and drive the sequence fetch -> cache -> refresh -> submit so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/util/parseFileContent.ts` / `if`
- Entrypoint: external link click
- Attacker controls: filename/path with traversal or extension mismatch; after a failed RPC response
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
