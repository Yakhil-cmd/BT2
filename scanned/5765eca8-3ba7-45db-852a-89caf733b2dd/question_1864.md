# Q1864: address-notification via handleAppend 1864

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `handleAppend` (packages/gui/src/components/addressbook/ContactAdd.tsx) control stale contact after edit/delete with a cached permission entry and drive the sequence open notification -> resolve details -> execute so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/ContactAdd.tsx` / `handleAppend`
- Entrypoint: announcement link/action flow
- Attacker controls: stale contact after edit/delete; with a cached permission entry
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
