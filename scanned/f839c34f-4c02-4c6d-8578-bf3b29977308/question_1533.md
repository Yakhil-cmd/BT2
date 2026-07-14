# Q1533: external-file-url via SandboxedIframe 1533

## Question
Can an unprivileged attacker entering through the imported file parse path in `SandboxedIframe` (packages/core/src/components/SandboxedIframe/SandboxedIframe.tsx) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion after canceling and reopening the dialog and drive the sequence connect -> approve -> switch context -> execute so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/SandboxedIframe/SandboxedIframe.tsx` / `SandboxedIframe`
- Entrypoint: imported file parse path
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; after canceling and reopening the dialog
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
