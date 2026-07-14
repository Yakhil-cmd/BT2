# Q2794: external-file-url via index 2794

## Question
Can an unprivileged attacker entering through the imported file parse path in `index` (packages/core/src/components/SandboxedIframe/index.ts) control filename/path with traversal or extension mismatch after a network switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/SandboxedIframe/index.ts` / `index`
- Entrypoint: imported file parse path
- Attacker controls: filename/path with traversal or extension mismatch; after a network switch
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
