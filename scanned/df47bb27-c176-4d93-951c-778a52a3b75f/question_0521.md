# Q521: external-file-url via parseFileContent 521

## Question
Can an unprivileged attacker entering through the imported file parse path in `parseFileContent` (packages/gui/src/util/parseFileContent.ts) control iframe content with navigation or message attempts with hidden Unicode characters and drive the sequence validate input -> normalize payload -> call RPC so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/util/parseFileContent.ts` / `parseFileContent`
- Entrypoint: imported file parse path
- Attacker controls: iframe content with navigation or message attempts; with hidden Unicode characters
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
