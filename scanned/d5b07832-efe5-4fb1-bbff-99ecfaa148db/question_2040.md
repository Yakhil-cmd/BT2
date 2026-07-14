# Q2040: nft-metadata via if 2040

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `if` (packages/gui/src/components/nfts/NFTRankings.tsx) control content hash/status fields that change across fetches with case-normalized identifiers and drive the sequence load persisted state -> render approval -> execute command so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTRankings.tsx` / `if`
- Entrypoint: multiple NFT download action
- Attacker controls: content hash/status fields that change across fetches; with case-normalized identifiers
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
