# Q2359: address-notification via if 2359

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `if` (packages/gui/src/hooks/usePayoutAddress.ts) control stale contact after edit/delete with a stale Redux cache and drive the sequence fetch -> cache -> refresh -> submit so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/usePayoutAddress.ts` / `if`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: stale contact after edit/delete; with a stale Redux cache
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
