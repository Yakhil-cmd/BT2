# Q1797: external-file-url via isValidURL 1797

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `isValidURL` (packages/core/src/utils/isValidURL.ts) control remote JSON changing between validation and use with hidden Unicode characters and drive the sequence load persisted state -> render approval -> execute command so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/utils/isValidURL.ts` / `isValidURL`
- Entrypoint: embedded iframe render path
- Attacker controls: remote JSON changing between validation and use; with hidden Unicode characters
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
