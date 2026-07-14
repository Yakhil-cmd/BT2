# Q1311: rpc-state via restrictions 1311

## Question
Can an unprivileged attacker entering through the service command response correlation in `restrictions` (packages/wallets/src/components/card/WalletCardCRCatRestrictions.tsx) control subscription event for a different wallet/fingerprint after canceling and reopening the dialog and drive the sequence connect -> approve -> switch context -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/card/WalletCardCRCatRestrictions.tsx` / `restrictions`
- Entrypoint: service command response correlation
- Attacker controls: subscription event for a different wallet/fingerprint; after canceling and reopening the dialog
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
