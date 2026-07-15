### Title
WalletConnect `chia_setNFTDID` Confirmation Dialog Spoofing via Mismatched `nft_launcher_id` / `nft_coin_ids` — (`packages/gui/src/electron/commands/Commands.ts`)

### Summary

The `chia_wallet.nft_set_nft_did` WalletConnect command definition lists `nft_launcher_id` and `nft_coin_ids` as two independent display parameters with no cross-validation. The confirmation dialog renders both raw values, but the daemon call exclusively uses `nft_coin_ids`. A malicious dApp can supply a recognizable victim-NFT launcher ID in `nft_launcher_id` while placing a different NFT's coin ID in `nft_coin_ids`, causing the user to approve a DID change for the wrong NFT.

### Finding Description

`Commands.ts` defines the `chia_wallet.nft_set_nft_did` command with the following `params` block: [1](#0-0) 

Both `nft_launcher_id` (type `string`) and `nft_coin_ids` (type `json`) are listed as independent display parameters. Neither the command registry nor any middleware validates that the coin IDs in `nft_coin_ids` actually belong to the NFT identified by `nft_launcher_id`.

The actual daemon call in `NFT.ts` uses only `nftCoinIds` — `nft_launcher_id` is never forwarded to the daemon: [2](#0-1) 

The WalletConnect execution path in `useWalletConnectCommand.tsx` passes the full, unmodified `commandParams` object (including the attacker-controlled `nft_launcher_id` and `nft_coin_ids`) directly to `window.permissionsAPI.dispatchAsPair` without any semantic validation: [3](#0-2) 

The `WalletConnectProvider` receives the raw dApp params and forwards them unchanged to `process`: [4](#0-3) 

### Impact Explanation

The NFT launcher ID (`nft1…` bech32m) is the stable, human-recognizable identifier for an NFT. The coin ID changes with every spend and is opaque to most users. A malicious dApp can:

1. Set `nft_launcher_id` to the launcher ID of a high-value NFT the user owns and recognizes.
2. Set `nft_coin_ids` to the coin ID of a *different* NFT in the same wallet.
3. The confirmation dialog renders both raw values side-by-side with no indication that they must correspond.
4. The user approves, believing they are setting the DID for the NFT shown by launcher ID.
5. The daemon executes `nft_set_nft_did` against the coin ID in `nft_coin_ids`, changing the DID association of the *wrong* NFT.

This causes the user to approve a DID assignment for a different NFT than displayed, satisfying the High-impact criterion: *"causes a user to approve… the wrong asset, identity, amount, destination, or status."*

### Likelihood Explanation

Any WalletConnect-connected dApp can craft this request. The user must have granted the dApp the `chia_setNFTDID` permission, but once granted, the attack requires only a single crafted JSON-RPC call. No additional privileges, leaked keys, or host compromise are needed. The attack is fully reproducible in a local test environment.

### Recommendation

In the main-process handler for `chia_wallet.nft_set_nft_did`, before presenting the confirmation dialog, resolve each coin ID in `nft_coin_ids` to its launcher ID (via `nft_get_info`) and assert that the resolved launcher ID matches the supplied `nft_launcher_id`. If they do not match, reject the request with an `INVALID_PARAMS` error. Alternatively, remove `nft_launcher_id` as a display-only parameter entirely and derive the human-readable NFT identity from `nft_coin_ids` server-side, so the display and execution paths share a single source of truth.

### Proof of Concept

```json
{
  "method": "chia_setNFTDID",
  "params": {
    "fingerprint": <victim_fingerprint>,
    "wallet_id": <victim_nft_wallet_id>,
    "nft_launcher_id": "<launcher_id_of_valuable_nft_A>",
    "nft_coin_ids": ["<current_coin_id_of_different_nft_B>"],
    "did": "<attacker_chosen_did>",
    "fee": 0
  }
}
```

Expected result: confirmation dialog shows `nft_launcher_id` = NFT-A's launcher ID; after user approval, the daemon executes `nft_set_nft_did` with NFT-B's coin ID, changing NFT-B's DID — not NFT-A's.

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L422-447)
```typescript
  'chia_wallet.nft_set_nft_did': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Move NFT to DID' }),
    message: () => i18n._(/* i18n */ { id: 'Are you sure you want to move this NFT to the specified profile?' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Move' }),
    params: [
      { name: 'wallet_id', label: () => i18n._(/* i18n */ { id: 'Wallet Id' }), type: 'number' },
      {
        name: 'nft_launcher_id',
        label: () => i18n._(/* i18n */ { id: 'NFT Launcher Id' }),
        type: 'string',
      },
      {
        name: 'nft_coin_ids',
        label: () => i18n._(/* i18n */ { id: 'NFT Coin Ids' }),
        type: 'json',
      },
      { name: 'did', label: () => i18n._(/* i18n */ { id: 'DID' }), type: 'string' },
      { name: 'fee', label: () => i18n._(/* i18n */ { id: 'Fee' }), type: 'bigint', humanize: 'mojo-to-xch' },
    ],
    dapp: [
      {
        command: 'chia_setNFTDID',
        title: () => i18n._(/* i18n */ { id: 'Set NFT DID' }),
      },
    ],
  },
```

**File:** packages/api/src/wallets/NFT.ts (L173-198)
```typescript
  async setNftDid(args: { walletId: number; nftCoinIds: string[]; did: string; fee: string } & AllowUnsyncedArg) {
    const { walletId, nftCoinIds, did, fee, allowUnsynced } = args;
    const extra = allowUnsynced != null ? { allowUnsynced } : {};
    if (nftCoinIds.length === 1) {
      return this.command<{
        walletId: number;
        spendBundle: SpendBundle;
      }>('nft_set_nft_did', {
        walletId,
        nftCoinId: nftCoinIds[0],
        didId: did,
        fee,
        ...extra,
      });
    }
    return this.command<{
      walletId: number[];
      spendBundle: SpendBundle;
      txNum: number;
    }>('nft_set_did_bulk', {
      nftCoinList: nftCoinIds.map((nftId: string) => ({ nft_coin_id: nftId, wallet_id: walletId })),
      didId: did,
      fee,
      ...extra,
    });
  }
```

**File:** packages/gui/src/hooks/useWalletConnectCommand.tsx (L84-99)
```typescript
    const commandParams = {
      ...params,
    };

    // remove old waitForConfirmation - back compatibility, we are using requiresSync instead
    if ('waitForConfirmation' in commandParams) {
      delete commandParams.waitForConfirmation;
    }

    log('Executing', command, commandParams);

    const result = await window.permissionsAPI.dispatchAsPair({
      topic: pairTopic,
      command,
      params: JSONbig.stringify(commandParams),
    });
```

**File:** packages/gui/src/components/walletConnect/WalletConnectProvider.tsx (L354-366)
```typescript
      const { fingerprint, ...rest } = params;
      const commandParams = {
        ...rest,
      };

      const parsedFingerprint = parseFingerprint(fingerprint);
      if (parsedFingerprint !== undefined) {
        commandParams.fingerprint = parsedFingerprint;
      }

      log('method', method, commandParams);

      const result = await currentProcess(pairTopic, method, commandParams, { mainnet: isMainnet });
```
