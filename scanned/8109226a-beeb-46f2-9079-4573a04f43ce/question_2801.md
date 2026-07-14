# Q2801: address-notification via match 2801

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `match` (packages/gui/src/components/addressbook/MyContact.tsx) control stale contact after edit/delete during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/MyContact.tsx` / `match`
- Entrypoint: burn/payout address helper
- Attacker controls: stale contact after edit/delete; during a pending modal confirmation
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
