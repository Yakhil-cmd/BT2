# Q660: nft-metadata via useHiddenNFTs 660

## Question
Can an unprivileged attacker entering through the external NFT link open action in `useHiddenNFTs` (packages/gui/src/hooks/useHiddenNFTs.ts) control HTML/SVG/media content rendered in preview after a network switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useHiddenNFTs.ts` / `useHiddenNFTs`
- Entrypoint: external NFT link open action
- Attacker controls: HTML/SVG/media content rendered in preview; after a network switch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
