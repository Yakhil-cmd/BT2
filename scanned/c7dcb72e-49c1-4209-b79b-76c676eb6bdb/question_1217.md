# Q1217: address-notification via SigningEntityWalletAddress 1217

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `SigningEntityWalletAddress` (packages/gui/src/components/signVerify/SigningEntityWalletAddress.tsx) control notification payload referencing offer/NFT/VC IDs during a pending modal confirmation and drive the sequence download or render content -> trigger linked wallet action so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/SigningEntityWalletAddress.tsx` / `SigningEntityWalletAddress`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; during a pending modal confirmation
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
