# Q3728: external-file-url via index 3728

## Question
Can an unprivileged attacker entering through the external link click in `index` (packages/core/src/components/SandboxedIframe/index.ts) control oversized or polyglot import file with precision-boundary values and drive the sequence import -> parse -> preview -> submit so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/SandboxedIframe/index.ts` / `index`
- Entrypoint: external link click
- Attacker controls: oversized or polyglot import file; with precision-boundary values
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
