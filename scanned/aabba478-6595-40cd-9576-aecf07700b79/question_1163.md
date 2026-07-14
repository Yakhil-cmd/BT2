# Q1163: offers via takerUnknownCATsLocal 1163

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `takerUnknownCATsLocal` (packages/gui/src/components/offers/OfferSummary.tsx) control conflicting offer IDs and secure-cancel flags through a batch of rapid user-accessible actions and drive the sequence preview -> mutate controlled state -> confirm so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferSummary.tsx` / `takerUnknownCATsLocal`
- Entrypoint: incoming offer notification open flow
- Attacker controls: conflicting offer IDs and secure-cancel flags; through a batch of rapid user-accessible actions
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
