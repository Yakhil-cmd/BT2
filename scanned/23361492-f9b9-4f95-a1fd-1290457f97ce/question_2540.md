# Q2540: address-notification via useNotifications 2540

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `useNotifications` (packages/gui/src/hooks/useNotifications.tsx) control announcement URL or action payload after a profile switch and drive the sequence import -> parse -> preview -> submit so the GUI would select a contact that displays one address while submitting another, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useNotifications.tsx` / `useNotifications`
- Entrypoint: announcement link/action flow
- Attacker controls: announcement URL or action payload; after a profile switch
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
