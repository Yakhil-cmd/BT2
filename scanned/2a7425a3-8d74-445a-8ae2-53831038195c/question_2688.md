# Q2688: address-notification via Notification 2688

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `Notification` (packages/gui/src/components/notification/Notification.tsx) control announcement URL or action payload after a failed RPC response and drive the sequence load persisted state -> render approval -> execute command so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/Notification.tsx` / `Notification`
- Entrypoint: contact selection in send forms
- Attacker controls: announcement URL or action payload; after a failed RPC response
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
