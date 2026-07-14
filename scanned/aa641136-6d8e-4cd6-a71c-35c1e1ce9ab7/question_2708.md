# Q2708: external-file-url via handleClick 2708

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `handleClick` (packages/core/src/components/Link/Link.tsx) control remote JSON changing between validation and use with a stale Redux cache and drive the sequence download or render content -> trigger linked wallet action so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/Link/Link.tsx` / `handleClick`
- Entrypoint: remote JSON fetch helper
- Attacker controls: remote JSON changing between validation and use; with a stale Redux cache
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
