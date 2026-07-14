# Q2999: nft-metadata via NFTProviderContext 2999

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTProviderContext` (packages/gui/src/components/nfts/provider/NFTProviderContext.ts) control HTML/SVG/media content rendered in preview with a cached permission entry and drive the sequence load persisted state -> render approval -> execute command so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/NFTProviderContext.ts` / `NFTProviderContext`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; with a cached permission entry
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
