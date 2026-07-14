# Q2470: external-file-url via useOpenExternal 2470

## Question
Can an unprivileged attacker entering through the imported file parse path in `useOpenExternal` (packages/core/src/hooks/useOpenExternal.ts) control remote JSON changing between validation and use with conflicting localStorage preferences and drive the sequence select -> edit backing object -> submit so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/hooks/useOpenExternal.ts` / `useOpenExternal`
- Entrypoint: imported file parse path
- Attacker controls: remote JSON changing between validation and use; with conflicting localStorage preferences
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
