# Q466: walletconnect via openPairDialog 466

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `openPairDialog` (packages/gui/src/electron/utils/openPairDialog.ts) control previously granted bypass permission combined with profile switch after canceling and reopening the dialog and drive the sequence download or render content -> trigger linked wallet action so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/openPairDialog.ts` / `openPairDialog`
- Entrypoint: stored dapp permission reload
- Attacker controls: previously granted bypass permission combined with profile switch; after canceling and reopening the dialog
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
