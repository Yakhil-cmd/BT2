# Q1740: rpc-state via fungibleAssetFromWalletIdAndAmount 1740

## Question
Can an unprivileged attacker entering through the service command response correlation in `fungibleAssetFromWalletIdAndAmount` (packages/api/src/utils/calculateRoyalties.ts) control subscription event for a different wallet/fingerprint with conflicting localStorage preferences and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/utils/calculateRoyalties.ts` / `fungibleAssetFromWalletIdAndAmount`
- Entrypoint: service command response correlation
- Attacker controls: subscription event for a different wallet/fingerprint; with conflicting localStorage preferences
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
