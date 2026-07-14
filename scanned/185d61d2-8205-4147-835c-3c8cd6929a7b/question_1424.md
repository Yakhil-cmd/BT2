# Q1424: address-notification via handleSetPayoutAddress 1424

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `handleSetPayoutAddress` (packages/gui/src/hooks/usePayoutAddress.ts) control notification payload referencing offer/NFT/VC IDs after canceling and reopening the dialog and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/usePayoutAddress.ts` / `handleSetPayoutAddress`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; after canceling and reopening the dialog
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
