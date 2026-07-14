# Q1982: external-file-url via SandboxedIframe 1982

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `SandboxedIframe` (packages/gui/src/electron/components/SandboxedIframe/SandboxedIframe.tsx) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/components/SandboxedIframe/SandboxedIframe.tsx` / `SandboxedIframe`
- Entrypoint: embedded iframe render path
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; through a batch of rapid user-accessible actions
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
