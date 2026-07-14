# Q3621: address-notification via filteredDids 3621

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `filteredDids` (packages/gui/src/components/addressbook/AddressBookSideBar.tsx) control stale contact after edit/delete with precision-boundary values and drive the sequence preview -> mutate controlled state -> confirm so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/AddressBookSideBar.tsx` / `filteredDids`
- Entrypoint: announcement link/action flow
- Attacker controls: stale contact after edit/delete; with precision-boundary values
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
