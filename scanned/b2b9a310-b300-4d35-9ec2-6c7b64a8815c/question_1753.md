# Q1753: address-notification via filterArray 1753

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `filterArray` (packages/gui/src/components/addressbook/AddressBookSideBar.tsx) control contact names and addresses with hidden characters after a failed RPC response and drive the sequence open notification -> resolve details -> execute so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/AddressBookSideBar.tsx` / `filterArray`
- Entrypoint: contact selection in send forms
- Attacker controls: contact names and addresses with hidden characters; after a failed RPC response
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
