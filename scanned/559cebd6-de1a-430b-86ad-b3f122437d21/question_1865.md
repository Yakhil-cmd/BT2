# Q1865: address-notification via handleAppend 1865

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `handleAppend` (packages/gui/src/components/addressbook/ContactEdit.tsx) control stale contact after edit/delete with a stale Redux cache and drive the sequence open notification -> resolve details -> execute so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/ContactEdit.tsx` / `handleAppend`
- Entrypoint: contact selection in send forms
- Attacker controls: stale contact after edit/delete; with a stale Redux cache
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
