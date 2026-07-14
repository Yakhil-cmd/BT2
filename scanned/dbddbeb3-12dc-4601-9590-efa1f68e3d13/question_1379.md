# Q1379: wallet-send via chiaToMojo 1379

## Question
Can an unprivileged attacker entering through the receive-address copy/new-address flow in `chiaToMojo` (packages/gui/src/electron/utils/chiaToMojo.ts) control clawback timelock fields combined with normal send fields with conflicting localStorage preferences and drive the sequence validate input -> normalize payload -> call RPC so the GUI would make the GUI submit a spend for a different wallet or asset than the confirmation showed, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/chiaToMojo.ts` / `chiaToMojo`
- Entrypoint: receive-address copy/new-address flow
- Attacker controls: clawback timelock fields combined with normal send fields; with conflicting localStorage preferences
- Exploit idea: make the GUI submit a spend for a different wallet or asset than the confirmation showed
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
