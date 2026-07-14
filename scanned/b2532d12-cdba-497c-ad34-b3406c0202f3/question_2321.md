# Q2321: external-file-url via isValidURL 2321

## Question
Can an unprivileged attacker entering through the external link click in `isValidURL` (packages/gui/src/electron/utils/isValidURL.ts) control remote JSON changing between validation and use with a cached permission entry and drive the sequence load persisted state -> render approval -> execute command so the GUI would parse file content differently from what the confirmation displays, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/isValidURL.ts` / `isValidURL`
- Entrypoint: external link click
- Attacker controls: remote JSON changing between validation and use; with a cached permission entry
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
