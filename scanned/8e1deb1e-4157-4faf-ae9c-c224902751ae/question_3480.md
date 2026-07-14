# Q3480: external-file-url via handleOpen 3480

## Question
Can an unprivileged attacker entering through the external link click in `handleOpen` (packages/gui/src/hooks/useOpenExternal.ts) control iframe content with navigation or message attempts with a delayed metadata fetch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useOpenExternal.ts` / `handleOpen`
- Entrypoint: external link click
- Attacker controls: iframe content with navigation or message attempts; with a delayed metadata fetch
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
