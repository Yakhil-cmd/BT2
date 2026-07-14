# Q520: external-file-url via parseFileContent 520

## Question
Can an unprivileged attacker entering through the external link click in `parseFileContent` (packages/gui/src/util/parseFileContent.ts) control iframe content with navigation or message attempts with hidden Unicode characters and drive the sequence open notification -> resolve details -> execute so the GUI would parse file content differently from what the confirmation displays, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/util/parseFileContent.ts` / `parseFileContent`
- Entrypoint: external link click
- Attacker controls: iframe content with navigation or message attempts; with hidden Unicode characters
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
