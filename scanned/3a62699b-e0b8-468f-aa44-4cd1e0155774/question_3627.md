# Q3627: address-notification via NotificationWrapper 3627

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `NotificationWrapper` (packages/gui/src/components/notification/NotificationWrapper.tsx) control announcement URL or action payload with case-normalized identifiers and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationWrapper.tsx` / `NotificationWrapper`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: announcement URL or action payload; with case-normalized identifiers
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
