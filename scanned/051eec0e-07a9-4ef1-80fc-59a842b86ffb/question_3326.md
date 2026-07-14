# Q3326: external-file-url via index 3326

## Question
Can an unprivileged attacker entering through the imported file parse path in `index` (packages/gui/src/electron/components/SandboxedIframe/index.ts) control remote JSON changing between validation and use after canceling and reopening the dialog and drive the sequence preview -> mutate controlled state -> confirm so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/components/SandboxedIframe/index.ts` / `index`
- Entrypoint: imported file parse path
- Attacker controls: remote JSON changing between validation and use; after canceling and reopening the dialog
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
