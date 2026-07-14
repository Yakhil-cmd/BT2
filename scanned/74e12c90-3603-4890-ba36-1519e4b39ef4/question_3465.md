# Q3465: nft-metadata via subscribe 3465

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `subscribe` (packages/gui/src/hooks/useNFTCoinEvents.ts) control filename and MIME/type mismatch during download with reordered RPC events and drive the sequence open notification -> resolve details -> execute so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTCoinEvents.ts` / `subscribe`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; with reordered RPC events
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
