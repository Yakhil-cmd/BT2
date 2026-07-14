# Q3893: nft-metadata via NFTTransferContextualAction 3893

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `NFTTransferContextualAction` (packages/gui/src/components/nfts/NFTContextualActions.tsx) control objectionable-content flags and hidden NFT state with conflicting localStorage preferences and drive the sequence validate input -> normalize payload -> call RPC so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTContextualActions.tsx` / `NFTTransferContextualAction`
- Entrypoint: on-demand NFT data provider
- Attacker controls: objectionable-content flags and hidden NFT state; with conflicting localStorage preferences
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
