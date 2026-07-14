# Q1372: external-file-url via canReadFile 1372

## Question
Can an unprivileged attacker entering through the save/download action in `canReadFile` (packages/gui/src/electron/utils/canReadFile.ts) control remote JSON changing between validation and use with conflicting localStorage preferences and drive the sequence validate input -> normalize payload -> call RPC so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/canReadFile.ts` / `canReadFile`
- Entrypoint: save/download action
- Attacker controls: remote JSON changing between validation and use; with conflicting localStorage preferences
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
