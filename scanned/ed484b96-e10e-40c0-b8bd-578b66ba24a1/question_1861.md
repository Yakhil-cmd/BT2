# Q1861: address-notification via index 1861

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `index` (packages/core/src/components/AddressBookProvider/index.ts) control contact names and addresses with hidden characters after a network switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/core/src/components/AddressBookProvider/index.ts` / `index`
- Entrypoint: announcement link/action flow
- Attacker controls: contact names and addresses with hidden characters; after a network switch
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
