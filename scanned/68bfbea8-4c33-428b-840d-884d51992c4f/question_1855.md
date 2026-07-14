# Q1855: rpc-state via removeHexPrefix 1855

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `removeHexPrefix` (packages/gui/src/util/removeHexPrefix.ts) control subscription event for a different wallet/fingerprint with a stale Redux cache and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/removeHexPrefix.ts` / `removeHexPrefix`
- Entrypoint: camel/snake case transform path
- Attacker controls: subscription event for a different wallet/fingerprint; with a stale Redux cache
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
