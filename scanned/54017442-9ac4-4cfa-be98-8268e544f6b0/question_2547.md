# Q2547: external-file-url via toggleSuppression 2547

## Question
Can an unprivileged attacker entering through the external link click in `toggleSuppression` (packages/gui/src/hooks/useOpenUnsafeLink.tsx) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion during a pending modal confirmation and drive the sequence connect -> approve -> switch context -> execute so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useOpenUnsafeLink.tsx` / `toggleSuppression`
- Entrypoint: external link click
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; during a pending modal confirmation
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
