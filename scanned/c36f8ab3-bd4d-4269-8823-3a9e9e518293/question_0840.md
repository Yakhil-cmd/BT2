# Q840: external-file-url via StyledBaseLink 840

## Question
Can an unprivileged attacker entering through the imported file parse path in `StyledBaseLink` (packages/core/src/components/Link/Link.tsx) control remote JSON changing between validation and use with a duplicate identifier and drive the sequence load persisted state -> render approval -> execute command so the GUI would parse file content differently from what the confirmation displays, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/Link/Link.tsx` / `StyledBaseLink`
- Entrypoint: imported file parse path
- Attacker controls: remote JSON changing between validation and use; with a duplicate identifier
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
