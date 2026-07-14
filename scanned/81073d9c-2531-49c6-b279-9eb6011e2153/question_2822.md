# Q2822: nft-metadata via remainingNFTWallets 2822

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `remainingNFTWallets` (packages/gui/src/components/nfts/NFTProfileDropdown.tsx) control objectionable-content flags and hidden NFT state with precision-boundary values and drive the sequence validate input -> normalize payload -> call RPC so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTProfileDropdown.tsx` / `remainingNFTWallets`
- Entrypoint: NFT preview dialog
- Attacker controls: objectionable-content flags and hidden NFT state; with precision-boundary values
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
