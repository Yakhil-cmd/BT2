# Q2695: address-notification via handleClick 2695

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `handleClick` (packages/gui/src/components/notification/NotificationsMenu.tsx) control burn or payout address returned from helper state after a network switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would select a contact that displays one address while submitting another, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationsMenu.tsx` / `handleClick`
- Entrypoint: notification preview/action flow
- Attacker controls: burn or payout address returned from helper state; after a network switch
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
