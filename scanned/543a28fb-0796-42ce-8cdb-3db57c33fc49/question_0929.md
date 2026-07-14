# Q929: external-file-url via index 929

## Question
Can an unprivileged attacker entering through the external link click in `index` (packages/core/src/components/Link/index.ts) control iframe content with navigation or message attempts with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would fetch private/local resources during normal GUI use, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/Link/index.ts` / `index`
- Entrypoint: external link click
- Attacker controls: iframe content with navigation or message attempts; with a redirected remote resource
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
