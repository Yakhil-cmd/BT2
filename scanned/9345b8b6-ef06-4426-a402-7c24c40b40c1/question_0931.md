# Q931: address-notification via AddressFields 931

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `AddressFields` (packages/gui/src/components/addressbook/ContactEdit.tsx) control stale contact after edit/delete after canceling and reopening the dialog and drive the sequence select -> edit backing object -> submit so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/ContactEdit.tsx` / `AddressFields`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: stale contact after edit/delete; after canceling and reopening the dialog
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
