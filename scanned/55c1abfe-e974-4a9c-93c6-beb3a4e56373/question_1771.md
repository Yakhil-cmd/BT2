# Q1771: rpc-state via VerifyMessage 1771

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `VerifyMessage` (packages/gui/src/components/signVerify/VerifyMessage.tsx) control subscription event for a different wallet/fingerprint with hidden Unicode characters and drive the sequence download or render content -> trigger linked wallet action so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/VerifyMessage.tsx` / `VerifyMessage`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; with hidden Unicode characters
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
