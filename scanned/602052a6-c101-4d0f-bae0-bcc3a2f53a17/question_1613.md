# Q1613: external-file-url via OpenUnsafeLinkConfirmationDialog 1613

## Question
Can an unprivileged attacker entering through the imported file parse path in `OpenUnsafeLinkConfirmationDialog` (packages/gui/src/hooks/useOpenUnsafeLink.tsx) control iframe content with navigation or message attempts with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useOpenUnsafeLink.tsx` / `OpenUnsafeLinkConfirmationDialog`
- Entrypoint: imported file parse path
- Attacker controls: iframe content with navigation or message attempts; with a redirected remote resource
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
