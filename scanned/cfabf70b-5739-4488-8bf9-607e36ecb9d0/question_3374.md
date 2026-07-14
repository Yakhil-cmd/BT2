# Q3374: wallet-send via normalizeHex 3374

## Question
Can an unprivileged attacker entering through the CAT send form submission in `normalizeHex` (packages/api/src/utils/normalizeHex.ts) control amount and fee strings near precision boundaries with hidden Unicode characters and drive the sequence import -> parse -> preview -> submit so the GUI would accept an address that displays as one target but serializes as another, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/api/src/utils/normalizeHex.ts` / `normalizeHex`
- Entrypoint: CAT send form submission
- Attacker controls: amount and fee strings near precision boundaries; with hidden Unicode characters
- Exploit idea: accept an address that displays as one target but serializes as another
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
