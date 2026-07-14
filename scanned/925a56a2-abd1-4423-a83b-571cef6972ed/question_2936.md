# Q2936: nft-metadata via useNFTCoinDIDSet 2936

## Question
Can an unprivileged attacker entering through the external NFT link open action in `useNFTCoinDIDSet` (packages/api-react/src/hooks/useNFTCoinDIDSet.ts) control objectionable-content flags and hidden NFT state with conflicting localStorage preferences and drive the sequence import -> parse -> preview -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinDIDSet.ts` / `useNFTCoinDIDSet`
- Entrypoint: external NFT link open action
- Attacker controls: objectionable-content flags and hidden NFT state; with conflicting localStorage preferences
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
