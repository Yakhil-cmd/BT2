# Q701: wallet-send via parseFee 701

## Question
Can an unprivileged attacker entering through the receive-address copy/new-address flow in `parseFee` (packages/gui/src/util/parseFee.ts) control amount and fee strings near precision boundaries with a stale Redux cache and drive the sequence import -> parse -> preview -> submit so the GUI would drop or alter clawback restrictions while still showing a clawback-protected send, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/util/parseFee.ts` / `parseFee`
- Entrypoint: receive-address copy/new-address flow
- Attacker controls: amount and fee strings near precision boundaries; with a stale Redux cache
- Exploit idea: drop or alter clawback restrictions while still showing a clawback-protected send
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
