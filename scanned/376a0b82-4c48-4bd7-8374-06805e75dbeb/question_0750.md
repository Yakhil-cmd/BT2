# Q750: rpc-state via Challenge 750

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `Challenge` (packages/api/src/@types/Challenge.ts) control subscription event for a different wallet/fingerprint with hidden Unicode characters and drive the sequence validate input -> normalize payload -> call RPC so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/Challenge.ts` / `Challenge`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; with hidden Unicode characters
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
