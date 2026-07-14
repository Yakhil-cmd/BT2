# Q3336: nft-metadata via useNFTCoinUpdated 3336

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `useNFTCoinUpdated` (packages/api-react/src/hooks/useNFTCoinUpdated.ts) control filename and MIME/type mismatch during download with a stale Redux cache and drive the sequence fetch -> cache -> refresh -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinUpdated.ts` / `useNFTCoinUpdated`
- Entrypoint: on-demand NFT data provider
- Attacker controls: filename and MIME/type mismatch during download; with a stale Redux cache
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
