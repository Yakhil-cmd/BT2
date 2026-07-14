# Q3731: external-file-url via index 3731

## Question
Can an unprivileged attacker entering through the save/download action in `index` (packages/core/src/components/Link/index.ts) control remote JSON changing between validation and use after a failed RPC response and drive the sequence import -> parse -> preview -> submit so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/Link/index.ts` / `index`
- Entrypoint: save/download action
- Attacker controls: remote JSON changing between validation and use; after a failed RPC response
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
