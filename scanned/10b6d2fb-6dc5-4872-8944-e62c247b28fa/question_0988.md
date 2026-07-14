# Q988: offers via OfferBuilderRoyaltyPayouts 988

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `OfferBuilderRoyaltyPayouts` (packages/gui/src/components/offers2/OfferBuilderRoyaltyPayouts.tsx) control offer bytes whose summary differs from displayed builder data after canceling and reopening the dialog and drive the sequence import -> parse -> preview -> submit so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderRoyaltyPayouts.tsx` / `OfferBuilderRoyaltyPayouts`
- Entrypoint: incoming offer notification open flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; after canceling and reopening the dialog
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
