# Q1752: address-notification via handleSelectContact 1752

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `handleSelectContact` (packages/gui/src/components/addressbook/AddressBookMenuItem.tsx) control announcement URL or action payload with a redirected remote resource and drive the sequence fetch -> cache -> refresh -> submit so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/AddressBookMenuItem.tsx` / `handleSelectContact`
- Entrypoint: contact selection in send forms
- Attacker controls: announcement URL or action payload; with a redirected remote resource
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
