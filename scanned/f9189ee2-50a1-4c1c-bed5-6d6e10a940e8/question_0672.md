# Q672: address-notification via useNotifications 672

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `useNotifications` (packages/gui/src/hooks/useNotifications.tsx) control burn or payout address returned from helper state with hidden Unicode characters and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useNotifications.tsx` / `useNotifications`
- Entrypoint: contact selection in send forms
- Attacker controls: burn or payout address returned from helper state; with hidden Unicode characters
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
