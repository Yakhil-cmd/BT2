# Q1393: wallet-send via mojoToChia 1393

## Question
Can an unprivileged attacker entering through the fee and amount conversion path in `mojoToChia` (packages/gui/src/electron/utils/mojoToChia.ts) control clawback timelock fields combined with normal send fields after canceling and reopening the dialog and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would drop or alter clawback restrictions while still showing a clawback-protected send, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/mojoToChia.ts` / `mojoToChia`
- Entrypoint: fee and amount conversion path
- Attacker controls: clawback timelock fields combined with normal send fields; after canceling and reopening the dialog
- Exploit idea: drop or alter clawback restrictions while still showing a clawback-protected send
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
