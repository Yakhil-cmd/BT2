# Q1387: external-file-url via if 1387

## Question
Can an unprivileged attacker entering through the imported file parse path in `if` (packages/gui/src/electron/utils/isValidURL.ts) control iframe content with navigation or message attempts after canceling and reopening the dialog and drive the sequence load persisted state -> render approval -> execute command so the GUI would fetch private/local resources during normal GUI use, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/isValidURL.ts` / `if`
- Entrypoint: imported file parse path
- Attacker controls: iframe content with navigation or message attempts; after canceling and reopening the dialog
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
