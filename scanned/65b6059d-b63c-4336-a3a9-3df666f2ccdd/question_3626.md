# Q3626: address-notification via handleClose 3626

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `handleClose` (packages/gui/src/components/notification/NotificationSendDialog.tsx) control burn or payout address returned from helper state through a batch of rapid user-accessible actions and drive the sequence download or render content -> trigger linked wallet action so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationSendDialog.tsx` / `handleClose`
- Entrypoint: announcement link/action flow
- Attacker controls: burn or payout address returned from helper state; through a batch of rapid user-accessible actions
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
