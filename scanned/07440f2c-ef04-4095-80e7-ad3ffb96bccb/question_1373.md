# Q1373: external-file-url via canReadFile 1373

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `canReadFile` (packages/gui/src/electron/utils/canReadFile.ts) control remote JSON changing between validation and use with conflicting localStorage preferences and drive the sequence validate input -> normalize payload -> call RPC so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/canReadFile.ts` / `canReadFile`
- Entrypoint: embedded iframe render path
- Attacker controls: remote JSON changing between validation and use; with conflicting localStorage preferences
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
