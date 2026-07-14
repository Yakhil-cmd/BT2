# Q1457: offers via if 1457

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `if` (packages/gui/src/util/prepareNFTOffer.ts) control royalty and fee fields near zero/rounding limits through a batch of rapid user-accessible actions and drive the sequence select -> edit backing object -> submit so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/prepareNFTOffer.ts` / `if`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: royalty and fee fields near zero/rounding limits; through a batch of rapid user-accessible actions
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
