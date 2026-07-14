# Q3486: external-file-url via saveOfferFile 3486

## Question
Can an unprivileged attacker entering through the save/download action in `saveOfferFile` (packages/gui/src/hooks/useSaveFile.ts) control iframe content with navigation or message attempts after a profile switch and drive the sequence import -> parse -> preview -> submit so the GUI would parse file content differently from what the confirmation displays, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useSaveFile.ts` / `saveOfferFile`
- Entrypoint: save/download action
- Attacker controls: iframe content with navigation or message attempts; after a profile switch
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
