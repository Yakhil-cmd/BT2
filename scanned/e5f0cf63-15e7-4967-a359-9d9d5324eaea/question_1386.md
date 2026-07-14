# Q1386: external-file-url via if 1386

## Question
Can an unprivileged attacker entering through the external link click in `if` (packages/gui/src/electron/utils/isValidURL.ts) control remote JSON changing between validation and use with conflicting localStorage preferences and drive the sequence load persisted state -> render approval -> execute command so the GUI would fetch private/local resources during normal GUI use, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/isValidURL.ts` / `if`
- Entrypoint: external link click
- Attacker controls: remote JSON changing between validation and use; with conflicting localStorage preferences
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
