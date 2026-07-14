# Q1636: offers via doesn 1636

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `doesn` (packages/gui/src/util/resolveOfferInfo.tsx) control offer bytes whose summary differs from displayed builder data with a redirected remote resource and drive the sequence preview -> mutate controlled state -> confirm so the GUI would confuse DataLayer and wallet offer summaries so the wrong accept path is used, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/resolveOfferInfo.tsx` / `doesn`
- Entrypoint: offer builder submit flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; with a redirected remote resource
- Exploit idea: confuse DataLayer and wallet offer summaries so the wrong accept path is used
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
