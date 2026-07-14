# Q3240: external-file-url via canReadFile 3240

## Question
Can an unprivileged attacker entering through the external link click in `canReadFile` (packages/gui/src/electron/utils/canReadFile.ts) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion with reordered RPC events and drive the sequence preview -> mutate controlled state -> confirm so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/canReadFile.ts` / `canReadFile`
- Entrypoint: external link click
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; with reordered RPC events
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
