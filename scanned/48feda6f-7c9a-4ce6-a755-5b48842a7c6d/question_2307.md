# Q2307: external-file-url via canReadFile 2307

## Question
Can an unprivileged attacker entering through the save/download action in `canReadFile` (packages/gui/src/electron/utils/canReadFile.ts) control iframe content with navigation or message attempts with a cached permission entry and drive the sequence load persisted state -> render approval -> execute command so the GUI would fetch private/local resources during normal GUI use, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/canReadFile.ts` / `canReadFile`
- Entrypoint: save/download action
- Attacker controls: iframe content with navigation or message attempts; with a cached permission entry
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
