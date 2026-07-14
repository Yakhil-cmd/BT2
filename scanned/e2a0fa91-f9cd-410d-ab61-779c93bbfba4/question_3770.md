# Q3770: offers via StyledPreviewContainer 3770

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `StyledPreviewContainer` (packages/gui/src/components/offers/NFTOfferPreview.tsx) control conflicting offer IDs and secure-cancel flags through a batch of rapid user-accessible actions and drive the sequence import -> parse -> preview -> submit so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/NFTOfferPreview.tsx` / `StyledPreviewContainer`
- Entrypoint: incoming offer notification open flow
- Attacker controls: conflicting offer IDs and secure-cancel flags; through a batch of rapid user-accessible actions
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
