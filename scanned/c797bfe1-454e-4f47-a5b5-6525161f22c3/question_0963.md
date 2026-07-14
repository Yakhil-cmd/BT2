# Q963: nft-metadata via useNFTDataOnDemand 963

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `useNFTDataOnDemand` (packages/gui/src/components/nfts/provider/hooks/useNFTDataOnDemand.ts) control filename and MIME/type mismatch during download through a batch of rapid user-accessible actions and drive the sequence connect -> approve -> switch context -> execute so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/hooks/useNFTDataOnDemand.ts` / `useNFTDataOnDemand`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; through a batch of rapid user-accessible actions
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
