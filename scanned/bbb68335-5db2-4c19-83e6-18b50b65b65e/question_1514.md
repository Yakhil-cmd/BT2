# Q1514: address-notification via nft 1514

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `nft` (packages/gui/src/components/notification/NotificationPreviewOffer.tsx) control announcement URL or action payload with a redirected remote resource and drive the sequence download or render content -> trigger linked wallet action so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationPreviewOffer.tsx` / `nft`
- Entrypoint: announcement link/action flow
- Attacker controls: announcement URL or action payload; with a redirected remote resource
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
