# Q3851: external-file-url via SandboxedIframe 3851

## Question
Can an unprivileged attacker entering through the save/download action in `SandboxedIframe` (packages/gui/src/electron/components/SandboxedIframe/SandboxedIframe.tsx) control remote JSON changing between validation and use with a duplicate identifier and drive the sequence import -> parse -> preview -> submit so the GUI would fetch private/local resources during normal GUI use, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/components/SandboxedIframe/SandboxedIframe.tsx` / `SandboxedIframe`
- Entrypoint: save/download action
- Attacker controls: remote JSON changing between validation and use; with a duplicate identifier
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
