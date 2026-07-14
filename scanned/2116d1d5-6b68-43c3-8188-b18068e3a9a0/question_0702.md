# Q702: offers via resolvePendingAssets 702

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `resolvePendingAssets` (packages/gui/src/util/resolveOfferInfo.tsx) control conflicting offer IDs and secure-cancel flags with case-normalized identifiers and drive the sequence fetch -> cache -> refresh -> submit so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/resolveOfferInfo.tsx` / `resolvePendingAssets`
- Entrypoint: incoming offer notification open flow
- Attacker controls: conflicting offer IDs and secure-cancel flags; with case-normalized identifiers
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
