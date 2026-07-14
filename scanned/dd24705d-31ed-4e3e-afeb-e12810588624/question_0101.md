# Q101: rpc-state via useHiddenWallet 101

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `useHiddenWallet` (packages/wallets/src/hooks/useHiddenWallet.ts) control subscription event for a different wallet/fingerprint with a duplicate identifier and drive the sequence connect -> approve -> switch context -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/hooks/useHiddenWallet.ts` / `useHiddenWallet`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; with a duplicate identifier
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
