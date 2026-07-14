# Q3456: address-notification via sortedNotifications 3456

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `sortedNotifications` (packages/gui/src/hooks/useBlockchainNotifications.tsx) control contact names and addresses with hidden characters with a cached permission entry and drive the sequence select -> edit backing object -> submit so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useBlockchainNotifications.tsx` / `sortedNotifications`
- Entrypoint: burn/payout address helper
- Attacker controls: contact names and addresses with hidden characters; with a cached permission entry
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
