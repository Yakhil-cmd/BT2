# Q3789: offers via handleAdd 3789

## Question
Can an unprivileged attacker entering through the crafted offer file import in `handleAdd` (packages/gui/src/components/offers2/OfferBuilderNFTSection.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with a duplicate identifier and drive the sequence preview -> mutate controlled state -> confirm so the GUI would confuse DataLayer and wallet offer summaries so the wrong accept path is used, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFTSection.tsx` / `handleAdd`
- Entrypoint: crafted offer file import
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with a duplicate identifier
- Exploit idea: confuse DataLayer and wallet offer summaries so the wrong accept path is used
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
