# Q503: address-notification via useWalletKeyAddresses 503

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `useWalletKeyAddresses` (packages/gui/src/hooks/useWalletKeyAddresses.ts) control stale contact after edit/delete through a batch of rapid user-accessible actions and drive the sequence download or render content -> trigger linked wallet action so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useWalletKeyAddresses.ts` / `useWalletKeyAddresses`
- Entrypoint: contact selection in send forms
- Attacker controls: stale contact after edit/delete; through a batch of rapid user-accessible actions
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
