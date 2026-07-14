# Q3335: nft-metadata via useNFTCoinRemoved 3335

## Question
Can an unprivileged attacker entering through the external NFT link open action in `useNFTCoinRemoved` (packages/api-react/src/hooks/useNFTCoinRemoved.ts) control filename and MIME/type mismatch during download with a stale Redux cache and drive the sequence fetch -> cache -> refresh -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinRemoved.ts` / `useNFTCoinRemoved`
- Entrypoint: external NFT link open action
- Attacker controls: filename and MIME/type mismatch during download; with a stale Redux cache
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
