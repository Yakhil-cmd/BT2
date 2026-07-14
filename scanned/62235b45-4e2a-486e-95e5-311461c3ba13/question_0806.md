# Q806: rpc-state via royaltyAssetFromNFTInfo 806

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `royaltyAssetFromNFTInfo` (packages/api/src/utils/calculateRoyalties.ts) control out-of-order event and query responses with a delayed metadata fetch and drive the sequence select -> edit backing object -> submit so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/utils/calculateRoyalties.ts` / `royaltyAssetFromNFTInfo`
- Entrypoint: camel/snake case transform path
- Attacker controls: out-of-order event and query responses; with a delayed metadata fetch
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
