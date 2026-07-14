# Q1774: external-file-url via Link 1774

## Question
Can an unprivileged attacker entering through the external link click in `Link` (packages/core/src/components/Link/Link.tsx) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion after canceling and reopening the dialog and drive the sequence preview -> mutate controlled state -> confirm so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/Link/Link.tsx` / `Link`
- Entrypoint: external link click
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; after canceling and reopening the dialog
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
