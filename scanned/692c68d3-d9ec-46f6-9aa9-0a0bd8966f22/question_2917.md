# Q2917: external-file-url via SandboxedIframe 2917

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `SandboxedIframe` (packages/gui/src/electron/components/SandboxedIframe/SandboxedIframe.tsx) control oversized or polyglot import file after a profile switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/components/SandboxedIframe/SandboxedIframe.tsx` / `SandboxedIframe`
- Entrypoint: embedded iframe render path
- Attacker controls: oversized or polyglot import file; after a profile switch
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
