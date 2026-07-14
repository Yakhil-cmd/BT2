# Q3729: address-notification via index 3729

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `index` (packages/core/src/components/AddressBookProvider/index.ts) control announcement URL or action payload after canceling and reopening the dialog and drive the sequence import -> parse -> preview -> submit so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/core/src/components/AddressBookProvider/index.ts` / `index`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: announcement URL or action payload; after canceling and reopening the dialog
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
