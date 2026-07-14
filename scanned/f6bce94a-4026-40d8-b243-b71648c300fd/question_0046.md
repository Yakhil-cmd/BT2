# Q46: offers via PreviewCard 46

## Question
Can an unprivileged attacker entering through the crafted offer file import in `PreviewCard` (packages/gui/src/components/offers2/OfferBuilderNFT.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries after canceling and reopening the dialog and drive the sequence select -> edit backing object -> submit so the GUI would confuse DataLayer and wallet offer summaries so the wrong accept path is used, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFT.tsx` / `PreviewCard`
- Entrypoint: crafted offer file import
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; after canceling and reopening the dialog
- Exploit idea: confuse DataLayer and wallet offer summaries so the wrong accept path is used
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
