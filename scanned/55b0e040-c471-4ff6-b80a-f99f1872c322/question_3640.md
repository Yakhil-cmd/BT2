# Q3640: address-notification via value 3640

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `value` (packages/core/src/components/AddressBookProvider/AddressBookProvider.tsx) control stale contact after edit/delete after a network switch and drive the sequence select -> edit backing object -> submit so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/core/src/components/AddressBookProvider/AddressBookProvider.tsx` / `value`
- Entrypoint: notification preview/action flow
- Attacker controls: stale contact after edit/delete; after a network switch
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
