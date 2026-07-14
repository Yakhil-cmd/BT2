# Q941: nft-metadata via getNftsCount 941

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `getNftsCount` (packages/api/src/wallets/NFT.ts) control metadata URI list with mixed schemes and redirects with reordered RPC events and drive the sequence select -> edit backing object -> submit so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/wallets/NFT.ts` / `getNftsCount`
- Entrypoint: NFT preview dialog
- Attacker controls: metadata URI list with mixed schemes and redirects; with reordered RPC events
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
