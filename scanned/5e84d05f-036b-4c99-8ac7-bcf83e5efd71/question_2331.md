# Q2331: wallet-send via normalizeHex 2331

## Question
Can an unprivileged attacker entering through the fee and amount conversion path in `normalizeHex` (packages/gui/src/electron/utils/normalizeHex.ts) control stale walletId from route or dropdown state after a network switch and drive the sequence import -> parse -> preview -> submit so the GUI would drop or alter clawback restrictions while still showing a clawback-protected send, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/normalizeHex.ts` / `normalizeHex`
- Entrypoint: fee and amount conversion path
- Attacker controls: stale walletId from route or dropdown state; after a network switch
- Exploit idea: drop or alter clawback restrictions while still showing a clawback-protected send
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
