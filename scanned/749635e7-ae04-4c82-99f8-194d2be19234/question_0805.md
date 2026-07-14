# Q805: rpc-state via ErrorData 805

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `ErrorData` (packages/api/src/utils/ErrorData.ts) control RPC error payload shaped like success through a batch of rapid user-accessible actions and drive the sequence preview -> mutate controlled state -> confirm so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/utils/ErrorData.ts` / `ErrorData`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; through a batch of rapid user-accessible actions
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
