# Q664: nft-metadata via useNFTFilter 664

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `useNFTFilter` (packages/gui/src/hooks/useNFTFilter.ts) control filename and MIME/type mismatch during download after a network switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTFilter.ts` / `useNFTFilter`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; after a network switch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
