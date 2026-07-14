# Q2333: external-file-url via openExternal 2333

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `openExternal` (packages/gui/src/electron/utils/openExternal.ts) control iframe content with navigation or message attempts during a pending modal confirmation and drive the sequence import -> parse -> preview -> submit so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/openExternal.ts` / `openExternal`
- Entrypoint: remote JSON fetch helper
- Attacker controls: iframe content with navigation or message attempts; during a pending modal confirmation
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
