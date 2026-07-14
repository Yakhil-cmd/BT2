# Q1534: address-notification via updateAddressBook 1534

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `updateAddressBook` (packages/core/src/hooks/useAddressBook.tsx) control stale contact after edit/delete with a delayed metadata fetch and drive the sequence select -> edit backing object -> submit so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/core/src/hooks/useAddressBook.tsx` / `updateAddressBook`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: stale contact after edit/delete; with a delayed metadata fetch
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
