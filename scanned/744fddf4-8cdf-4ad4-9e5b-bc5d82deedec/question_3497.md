# Q3497: external-file-url via if 3497

## Question
Can an unprivileged attacker entering through the save/download action in `if` (packages/gui/src/util/getFileExtension.ts) control oversized or polyglot import file with a duplicate identifier and drive the sequence preview -> mutate controlled state -> confirm so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/util/getFileExtension.ts` / `if`
- Entrypoint: save/download action
- Attacker controls: oversized or polyglot import file; with a duplicate identifier
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
