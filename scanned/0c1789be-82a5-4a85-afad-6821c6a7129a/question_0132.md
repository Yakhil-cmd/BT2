# Q132: nft-metadata via useGetNFTWallets 132

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `useGetNFTWallets` (packages/api-react/src/hooks/useGetNFTWallets.ts) control objectionable-content flags and hidden NFT state after canceling and reopening the dialog and drive the sequence validate input -> normalize payload -> call RPC so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useGetNFTWallets.ts` / `useGetNFTWallets`
- Entrypoint: on-demand NFT data provider
- Attacker controls: objectionable-content flags and hidden NFT state; after canceling and reopening the dialog
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
