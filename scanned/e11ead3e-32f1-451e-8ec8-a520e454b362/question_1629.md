# Q1629: external-file-url via if 1629

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `if` (packages/gui/src/util/getFileExtension.ts) control iframe content with navigation or message attempts after a failed RPC response and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/util/getFileExtension.ts` / `if`
- Entrypoint: remote JSON fetch helper
- Attacker controls: iframe content with navigation or message attempts; after a failed RPC response
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
