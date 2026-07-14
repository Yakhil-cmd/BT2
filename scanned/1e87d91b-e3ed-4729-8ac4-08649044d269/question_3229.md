# Q3229: external-file-url via LinkAPI 3229

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `LinkAPI` (packages/gui/src/electron/constants/LinkAPI.ts) control remote JSON changing between validation and use during a pending modal confirmation and drive the sequence open notification -> resolve details -> execute so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/constants/LinkAPI.ts` / `LinkAPI`
- Entrypoint: remote JSON fetch helper
- Attacker controls: remote JSON changing between validation and use; during a pending modal confirmation
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
