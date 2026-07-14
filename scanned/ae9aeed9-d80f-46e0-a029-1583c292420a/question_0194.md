# Q194: nft-metadata via NFTProvider 194

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `NFTProvider` (packages/gui/src/components/nfts/provider/NFTProvider.tsx) control metadata URI list with mixed schemes and redirects with conflicting localStorage preferences and drive the sequence open notification -> resolve details -> execute so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/NFTProvider.tsx` / `NFTProvider`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: metadata URI list with mixed schemes and redirects; with conflicting localStorage preferences
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
