# Q1590: external-file-url via useEnableFilePropagationServer 1590

## Question
Can an unprivileged attacker entering through the external link click in `useEnableFilePropagationServer` (packages/gui/src/hooks/useEnableFilePropagationServer.ts) control iframe content with navigation or message attempts with hidden Unicode characters and drive the sequence connect -> approve -> switch context -> execute so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useEnableFilePropagationServer.ts` / `useEnableFilePropagationServer`
- Entrypoint: external link click
- Attacker controls: iframe content with navigation or message attempts; with hidden Unicode characters
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
