# Q1760: address-notification via NotificationsDropdown 1760

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `NotificationsDropdown` (packages/gui/src/components/notification/NotificationsDropdown.tsx) control announcement URL or action payload after a profile switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationsDropdown.tsx` / `NotificationsDropdown`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: announcement URL or action payload; after a profile switch
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
