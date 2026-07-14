# Q1863: external-file-url via index 1863

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `index` (packages/core/src/components/Link/index.ts) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion during a pending modal confirmation and drive the sequence load persisted state -> render approval -> execute command so the GUI would parse file content differently from what the confirmation displays, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/Link/index.ts` / `index`
- Entrypoint: remote JSON fetch helper
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; during a pending modal confirmation
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
