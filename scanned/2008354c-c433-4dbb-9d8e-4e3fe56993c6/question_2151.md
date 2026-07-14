# Q2151: address-notification via SigningEntityWalletAddress 2151

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `SigningEntityWalletAddress` (packages/gui/src/components/signVerify/SigningEntityWalletAddress.tsx) control announcement URL or action payload with hidden Unicode characters and drive the sequence import -> parse -> preview -> submit so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/SigningEntityWalletAddress.tsx` / `SigningEntityWalletAddress`
- Entrypoint: contact selection in send forms
- Attacker controls: announcement URL or action payload; with hidden Unicode characters
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
