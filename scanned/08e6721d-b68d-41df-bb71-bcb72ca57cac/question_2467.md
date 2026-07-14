# Q2467: external-file-url via handleLoad 2467

## Question
Can an unprivileged attacker entering through the external link click in `handleLoad` (packages/core/src/components/SandboxedIframe/SandboxedIframe.tsx) control oversized or polyglot import file with a stale Redux cache and drive the sequence download or render content -> trigger linked wallet action so the GUI would fetch private/local resources during normal GUI use, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/SandboxedIframe/SandboxedIframe.tsx` / `handleLoad`
- Entrypoint: external link click
- Attacker controls: oversized or polyglot import file; with a stale Redux cache
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
