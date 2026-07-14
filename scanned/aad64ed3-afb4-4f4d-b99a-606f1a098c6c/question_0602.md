# Q602: external-file-url via useOpenExternal 602

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `useOpenExternal` (packages/core/src/hooks/useOpenExternal.ts) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion with a stale Redux cache and drive the sequence import -> parse -> preview -> submit so the GUI would fetch private/local resources during normal GUI use, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/hooks/useOpenExternal.ts` / `useOpenExternal`
- Entrypoint: embedded iframe render path
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; with a stale Redux cache
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
