# Q2800: address-notification via handleRemove 2800

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `handleRemove` (packages/gui/src/components/addressbook/ContactSummary.tsx) control contact names and addresses with hidden characters with hidden Unicode characters and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/ContactSummary.tsx` / `handleRemove`
- Entrypoint: announcement link/action flow
- Attacker controls: contact names and addresses with hidden characters; with hidden Unicode characters
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
