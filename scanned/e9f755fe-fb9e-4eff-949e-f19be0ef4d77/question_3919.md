# Q3919: nft-metadata via NFTs 3919

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `NFTs` (packages/gui/src/components/nfts/NFTs.tsx) control metadata URI list with mixed schemes and redirects after a failed RPC response and drive the sequence open notification -> resolve details -> execute so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTs.tsx` / `NFTs`
- Entrypoint: on-demand NFT data provider
- Attacker controls: metadata URI list with mixed schemes and redirects; after a failed RPC response
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
