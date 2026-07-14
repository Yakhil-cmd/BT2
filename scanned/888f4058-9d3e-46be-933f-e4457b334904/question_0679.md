# Q679: external-file-url via InvalidURLWarningDialog 679

## Question
Can an unprivileged attacker entering through the save/download action in `InvalidURLWarningDialog` (packages/gui/src/hooks/useOpenUnsafeLink.tsx) control iframe content with navigation or message attempts with case-normalized identifiers and drive the sequence open notification -> resolve details -> execute so the GUI would parse file content differently from what the confirmation displays, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useOpenUnsafeLink.tsx` / `InvalidURLWarningDialog`
- Entrypoint: save/download action
- Attacker controls: iframe content with navigation or message attempts; with case-normalized identifiers
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
