# Q2797: external-file-url via index 2797

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `index` (packages/core/src/components/Link/index.ts) control oversized or polyglot import file with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/Link/index.ts` / `index`
- Entrypoint: embedded iframe render path
- Attacker controls: oversized or polyglot import file; with hidden Unicode characters
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
