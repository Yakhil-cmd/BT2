# Q2689: address-notification via handleClick 2689

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `handleClick` (packages/gui/src/components/notification/NotificationAnnouncement.tsx) control announcement URL or action payload with case-normalized identifiers and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationAnnouncement.tsx` / `handleClick`
- Entrypoint: announcement link/action flow
- Attacker controls: announcement URL or action payload; with case-normalized identifiers
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
