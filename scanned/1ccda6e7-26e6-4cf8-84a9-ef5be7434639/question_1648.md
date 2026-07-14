# Q1648: rpc-state via useForceUpdate 1648

## Question
Can an unprivileged attacker entering through the service command response correlation in `useForceUpdate` (packages/api-react/src/hooks/useForceUpdate.ts) control subscription event for a different wallet/fingerprint during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/hooks/useForceUpdate.ts` / `useForceUpdate`
- Entrypoint: service command response correlation
- Attacker controls: subscription event for a different wallet/fingerprint; during a pending modal confirmation
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
