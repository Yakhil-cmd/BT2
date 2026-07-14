# Q2389: external-file-url via parseFileContent 2389

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `parseFileContent` (packages/gui/src/util/parseFileContent.ts) control oversized or polyglot import file after a network switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/util/parseFileContent.ts` / `parseFileContent`
- Entrypoint: remote JSON fetch helper
- Attacker controls: oversized or polyglot import file; after a network switch
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
