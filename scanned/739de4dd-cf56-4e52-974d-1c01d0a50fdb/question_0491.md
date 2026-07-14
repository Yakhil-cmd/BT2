# Q491: address-notification via usePayoutAddress 491

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `usePayoutAddress` (packages/gui/src/hooks/usePayoutAddress.ts) control burn or payout address returned from helper state with a duplicate identifier and drive the sequence fetch -> cache -> refresh -> submit so the GUI would select a contact that displays one address while submitting another, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/usePayoutAddress.ts` / `usePayoutAddress`
- Entrypoint: announcement link/action flow
- Attacker controls: burn or payout address returned from helper state; with a duplicate identifier
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
