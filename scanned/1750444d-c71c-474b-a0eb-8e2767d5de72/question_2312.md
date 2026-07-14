# Q2312: wallet-send via chiaToMojo 2312

## Question
Can an unprivileged attacker entering through the CAT send form submission in `chiaToMojo` (packages/gui/src/electron/utils/chiaToMojo.ts) control destination address with mixed prefix/case or hidden characters with a cached permission entry and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would accept an address that displays as one target but serializes as another, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/chiaToMojo.ts` / `chiaToMojo`
- Entrypoint: CAT send form submission
- Attacker controls: destination address with mixed prefix/case or hidden characters; with a cached permission entry
- Exploit idea: accept an address that displays as one target but serializes as another
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
