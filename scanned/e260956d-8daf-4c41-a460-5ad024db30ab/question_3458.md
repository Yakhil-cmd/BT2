# Q3458: external-file-url via useEnableFilePropagationServer 3458

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `useEnableFilePropagationServer` (packages/gui/src/hooks/useEnableFilePropagationServer.ts) control oversized or polyglot import file after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would fetch private/local resources during normal GUI use, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useEnableFilePropagationServer.ts` / `useEnableFilePropagationServer`
- Entrypoint: embedded iframe render path
- Attacker controls: oversized or polyglot import file; after a network switch
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
