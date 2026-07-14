# Q2213: rpc-state via WalletHeader 2213

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `WalletHeader` (packages/wallets/src/components/WalletHeader.tsx) control large numeric fields near JS precision limits with case-normalized identifiers and drive the sequence connect -> approve -> switch context -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletHeader.tsx` / `WalletHeader`
- Entrypoint: daemon RPC response handling
- Attacker controls: large numeric fields near JS precision limits; with case-normalized identifiers
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
