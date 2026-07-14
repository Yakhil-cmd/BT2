# Q3404: external-file-url via handleOpen 3404

## Question
Can an unprivileged attacker entering through the external link click in `handleOpen` (packages/core/src/hooks/useOpenExternal.ts) control iframe content with navigation or message attempts with a cached permission entry and drive the sequence import -> parse -> preview -> submit so the GUI would fetch private/local resources during normal GUI use, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/hooks/useOpenExternal.ts` / `handleOpen`
- Entrypoint: external link click
- Attacker controls: iframe content with navigation or message attempts; with a cached permission entry
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
