# Q817: address-notification via AddressBook 817

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `AddressBook` (packages/gui/src/components/addressbook/AddressBook.tsx) control stale contact after edit/delete after a profile switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/AddressBook.tsx` / `AddressBook`
- Entrypoint: notification preview/action flow
- Attacker controls: stale contact after edit/delete; after a profile switch
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
