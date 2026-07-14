# Q1299: rpc-state via showedName 1299

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `showedName` (packages/wallets/src/components/WalletTokenCard.tsx) control RPC error payload shaped like success with case-normalized identifiers and drive the sequence download or render content -> trigger linked wallet action so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletTokenCard.tsx` / `showedName`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; with case-normalized identifiers
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
