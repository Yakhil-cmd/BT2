# Q2523: address-notification via useBurnAddress 2523

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `useBurnAddress` (packages/gui/src/hooks/useBurnAddress.ts) control burn or payout address returned from helper state after a failed RPC response and drive the sequence load persisted state -> render approval -> execute command so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useBurnAddress.ts` / `useBurnAddress`
- Entrypoint: announcement link/action flow
- Attacker controls: burn or payout address returned from helper state; after a failed RPC response
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
