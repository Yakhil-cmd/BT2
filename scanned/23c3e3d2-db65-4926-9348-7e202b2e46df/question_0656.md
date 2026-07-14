# Q656: external-file-url via useEnableFilePropagationServer 656

## Question
Can an unprivileged attacker entering through the imported file parse path in `useEnableFilePropagationServer` (packages/gui/src/hooks/useEnableFilePropagationServer.ts) control remote JSON changing between validation and use during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would fetch private/local resources during normal GUI use, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useEnableFilePropagationServer.ts` / `useEnableFilePropagationServer`
- Entrypoint: imported file parse path
- Attacker controls: remote JSON changing between validation and use; during a pending modal confirmation
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
