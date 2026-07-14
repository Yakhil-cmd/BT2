# Q3260: wallet-send via mojoToChia 3260

## Question
Can an unprivileged attacker entering through the wallet RPC send command in `mojoToChia` (packages/gui/src/electron/utils/mojoToChia.ts) control amount and fee strings near precision boundaries with a delayed metadata fetch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would round or normalize amount/fee differently between display and RPC payload, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/mojoToChia.ts` / `mojoToChia`
- Entrypoint: wallet RPC send command
- Attacker controls: amount and fee strings near precision boundaries; with a delayed metadata fetch
- Exploit idea: round or normalize amount/fee differently between display and RPC payload
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
