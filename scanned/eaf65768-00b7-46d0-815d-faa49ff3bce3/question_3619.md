# Q3619: address-notification via AddressBook 3619

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `AddressBook` (packages/gui/src/components/addressbook/AddressBook.tsx) control announcement URL or action payload with a cached permission entry and drive the sequence download or render content -> trigger linked wallet action so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/AddressBook.tsx` / `AddressBook`
- Entrypoint: burn/payout address helper
- Attacker controls: announcement URL or action payload; with a cached permission entry
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
