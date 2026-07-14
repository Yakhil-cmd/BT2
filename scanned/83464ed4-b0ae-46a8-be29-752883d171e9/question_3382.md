# Q3382: address-notification via NotificationPreviewOffer 3382

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `NotificationPreviewOffer` (packages/gui/src/components/notification/NotificationPreviewOffer.tsx) control notification payload referencing offer/NFT/VC IDs with hidden Unicode characters and drive the sequence select -> edit backing object -> submit so the GUI would select a contact that displays one address while submitting another, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationPreviewOffer.tsx` / `NotificationPreviewOffer`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with hidden Unicode characters
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
