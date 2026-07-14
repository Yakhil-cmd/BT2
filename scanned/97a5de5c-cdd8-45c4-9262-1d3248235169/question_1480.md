# Q1480: nft-metadata via NFTInfo 1480

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NFTInfo` (packages/api/src/@types/NFTInfo.ts) control metadata URI list with mixed schemes and redirects with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/@types/NFTInfo.ts` / `NFTInfo`
- Entrypoint: external NFT link open action
- Attacker controls: metadata URI list with mixed schemes and redirects; with hidden Unicode characters
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
