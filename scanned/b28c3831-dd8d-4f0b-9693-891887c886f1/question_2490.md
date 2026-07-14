# Q2490: rpc-state via UnitValue 2490

## Question
Can an unprivileged attacker entering through the RTK query cache update in `UnitValue` (packages/gui/src/electron/constants/UnitValue.ts) control subscription event for a different wallet/fingerprint after a network switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/constants/UnitValue.ts` / `UnitValue`
- Entrypoint: RTK query cache update
- Attacker controls: subscription event for a different wallet/fingerprint; after a network switch
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
