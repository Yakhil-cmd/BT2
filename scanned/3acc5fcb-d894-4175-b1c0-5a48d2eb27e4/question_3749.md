# Q3749: rpc-state via addVCProofs 3749

## Question
Can an unprivileged attacker entering through the service command response correlation in `addVCProofs` (packages/api/src/wallets/VC.ts) control response object with duplicate camelCase/snake_case keys after a network switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/VC.ts` / `addVCProofs`
- Entrypoint: service command response correlation
- Attacker controls: response object with duplicate camelCase/snake_case keys; after a network switch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
