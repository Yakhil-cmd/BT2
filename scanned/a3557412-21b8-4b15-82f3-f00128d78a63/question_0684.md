# Q684: external-file-url via useSaveFile 684

## Question
Can an unprivileged attacker entering through the external link click in `useSaveFile` (packages/gui/src/hooks/useSaveFile.ts) control remote JSON changing between validation and use during a pending modal confirmation and drive the sequence fetch -> cache -> refresh -> submit so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useSaveFile.ts` / `useSaveFile`
- Entrypoint: external link click
- Attacker controls: remote JSON changing between validation and use; during a pending modal confirmation
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
