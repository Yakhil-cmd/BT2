# Q932: address-notification via ContactSummary 932

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `ContactSummary` (packages/gui/src/components/addressbook/ContactSummary.tsx) control burn or payout address returned from helper state with a redirected remote resource and drive the sequence open notification -> resolve details -> execute so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/ContactSummary.tsx` / `ContactSummary`
- Entrypoint: contact selection in send forms
- Attacker controls: burn or payout address returned from helper state; with a redirected remote resource
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
