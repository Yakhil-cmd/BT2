# Q3620: address-notification via AddressBookMenuItem 3620

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `AddressBookMenuItem` (packages/gui/src/components/addressbook/AddressBookMenuItem.tsx) control contact names and addresses with hidden characters with hidden Unicode characters and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/AddressBookMenuItem.tsx` / `AddressBookMenuItem`
- Entrypoint: announcement link/action flow
- Attacker controls: contact names and addresses with hidden characters; with hidden Unicode characters
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
