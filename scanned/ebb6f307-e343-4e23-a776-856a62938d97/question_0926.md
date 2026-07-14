# Q926: external-file-url via index 926

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `index` (packages/core/src/components/SandboxedIframe/index.ts) control remote JSON changing between validation and use with case-normalized identifiers and drive the sequence validate input -> normalize payload -> call RPC so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/SandboxedIframe/index.ts` / `index`
- Entrypoint: embedded iframe render path
- Attacker controls: remote JSON changing between validation and use; with case-normalized identifiers
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
