# Q1867: address-notification via newLabel 1867

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `newLabel` (packages/gui/src/components/addressbook/MyContact.tsx) control contact names and addresses with hidden characters with a redirected remote resource and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/MyContact.tsx` / `newLabel`
- Entrypoint: contact selection in send forms
- Attacker controls: contact names and addresses with hidden characters; with a redirected remote resource
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
