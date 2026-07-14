# Q486: nft-metadata via useNFTMetadataLRU 486

## Question
Can an unprivileged attacker entering through the external NFT link open action in `useNFTMetadataLRU` (packages/gui/src/hooks/useNFTMetadataLRU.ts) control filename and MIME/type mismatch during download with precision-boundary values and drive the sequence select -> edit backing object -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTMetadataLRU.ts` / `useNFTMetadataLRU`
- Entrypoint: external NFT link open action
- Attacker controls: filename and MIME/type mismatch during download; with precision-boundary values
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
