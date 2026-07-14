# Q35: offers via StyledPreviewContainer 35

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `StyledPreviewContainer` (packages/gui/src/components/offers/NFTOfferPreview.tsx) control conflicting offer IDs and secure-cancel flags with case-normalized identifiers and drive the sequence select -> edit backing object -> submit so the GUI would make the user approve one offer summary while the RPC accepts different offered/requested assets, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/NFTOfferPreview.tsx` / `StyledPreviewContainer`
- Entrypoint: incoming offer notification open flow
- Attacker controls: conflicting offer IDs and secure-cancel flags; with case-normalized identifiers
- Exploit idea: make the user approve one offer summary while the RPC accepts different offered/requested assets
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
