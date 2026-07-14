# Q1822: address-notification via SettingsNotifications 1822

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `SettingsNotifications` (packages/gui/src/components/settings/SettingsNotifications.tsx) control stale contact after edit/delete during a pending modal confirmation and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/settings/SettingsNotifications.tsx` / `SettingsNotifications`
- Entrypoint: burn/payout address helper
- Attacker controls: stale contact after edit/delete; during a pending modal confirmation
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
