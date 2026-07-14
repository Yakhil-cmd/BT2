# Q3946: offers via handleReset 3946

## Question
Can an unprivileged attacker entering through the crafted offer file import in `handleReset` (packages/gui/src/components/offers/OfferEditor.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with hidden Unicode characters and drive the sequence select -> edit backing object -> submit so the GUI would confuse DataLayer and wallet offer summaries so the wrong accept path is used, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferEditor.tsx` / `handleReset`
- Entrypoint: crafted offer file import
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with hidden Unicode characters
- Exploit idea: confuse DataLayer and wallet offer summaries so the wrong accept path is used
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
