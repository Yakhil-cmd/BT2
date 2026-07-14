# Q1618: external-file-url via saveOfferFile 1618

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `saveOfferFile` (packages/gui/src/hooks/useSaveFile.ts) control oversized or polyglot import file with hidden Unicode characters and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useSaveFile.ts` / `saveOfferFile`
- Entrypoint: remote JSON fetch helper
- Attacker controls: oversized or polyglot import file; with hidden Unicode characters
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
