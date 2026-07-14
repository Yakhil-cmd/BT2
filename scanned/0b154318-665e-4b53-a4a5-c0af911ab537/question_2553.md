# Q2553: address-notification via useShowNotification 2553

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `useShowNotification` (packages/gui/src/hooks/useShowNotification.ts) control burn or payout address returned from helper state with a delayed metadata fetch and drive the sequence open notification -> resolve details -> execute so the GUI would select a contact that displays one address while submitting another, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useShowNotification.ts` / `useShowNotification`
- Entrypoint: announcement link/action flow
- Attacker controls: burn or payout address returned from helper state; with a delayed metadata fetch
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
