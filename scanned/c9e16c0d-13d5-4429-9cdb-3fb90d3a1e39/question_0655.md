# Q655: address-notification via useBurnAddress 655

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `useBurnAddress` (packages/gui/src/hooks/useBurnAddress.ts) control announcement URL or action payload during a pending modal confirmation and drive the sequence select -> edit backing object -> submit so the GUI would select a contact that displays one address while submitting another, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useBurnAddress.ts` / `useBurnAddress`
- Entrypoint: contact selection in send forms
- Attacker controls: announcement URL or action payload; during a pending modal confirmation
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
