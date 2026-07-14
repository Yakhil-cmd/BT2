# Q943: nft-metadata via getNftsCount 943

## Question
Can an unprivileged attacker entering through the external NFT link open action in `getNftsCount` (packages/api/src/wallets/NFT.ts) control content hash/status fields that change across fetches with reordered RPC events and drive the sequence select -> edit backing object -> submit so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/wallets/NFT.ts` / `getNftsCount`
- Entrypoint: external NFT link open action
- Attacker controls: content hash/status fields that change across fetches; with reordered RPC events
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
