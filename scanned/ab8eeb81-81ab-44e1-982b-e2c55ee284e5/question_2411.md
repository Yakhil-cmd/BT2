# Q2411: nft-metadata via DataLayerRootHash 2411

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `DataLayerRootHash` (packages/api/src/@types/DataLayerRootHash.ts) control metadata URI list with mixed schemes and redirects with precision-boundary values and drive the sequence connect -> approve -> switch context -> execute so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/@types/DataLayerRootHash.ts` / `DataLayerRootHash`
- Entrypoint: on-demand NFT data provider
- Attacker controls: metadata URI list with mixed schemes and redirects; with precision-boundary values
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
