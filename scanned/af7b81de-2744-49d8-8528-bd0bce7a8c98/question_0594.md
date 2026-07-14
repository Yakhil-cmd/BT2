# Q594: rpc-state via CrCatFlags 594

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `CrCatFlags` (packages/wallets/src/components/crCat/CrCatFlags.tsx) control RPC error payload shaped like success with case-normalized identifiers and drive the sequence open notification -> resolve details -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/crCat/CrCatFlags.tsx` / `CrCatFlags`
- Entrypoint: daemon RPC response handling
- Attacker controls: RPC error payload shaped like success; with case-normalized identifiers
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
