# Q3481: external-file-url via useOpenUnsafeLink 3481

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `useOpenUnsafeLink` (packages/gui/src/hooks/useOpenUnsafeLink.tsx) control oversized or polyglot import file with hidden Unicode characters and drive the sequence select -> edit backing object -> submit so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useOpenUnsafeLink.tsx` / `useOpenUnsafeLink`
- Entrypoint: remote JSON fetch helper
- Attacker controls: oversized or polyglot import file; with hidden Unicode characters
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
