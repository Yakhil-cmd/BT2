### Title
WalletConnect `chia_sendTransaction` Hides `wallet_id` from Confirmation Display, Enabling CAT-for-XCH Asset Substitution — (File: `packages/gui/src/electron/commands/Commands.ts`)

---

### Summary

A paired dApp with `chia_sendTransaction` permission can pass an arbitrary `wallet_id` (e.g., a CAT token wallet) while the confirmation dialog always humanizes the `amount` field as XCH. The user approves what appears to be a small XCH transfer but actually executes a CAT token transfer of a completely different magnitude and asset type.

---

### Finding Description

The `chia_wallet.send_transaction` command schema defines `wallet_id` as an accepted parameter with `hide: true` and a default of `1` (the standard XCH wallet): [1](#0-0) 

Because the dapp entry for `chia_sendTransaction` does not override `params`, `DappCommands.ts` inherits the full parent param list including `wallet_id`: [2](#0-1) 

`parseDappParams` validates that every key in the dApp's payload exists in the inherited param map. Since `wallet_id` is in that map, a dApp may freely supply any numeric wallet ID: [3](#0-2) 

The confirmation dialog humanizes `amount` as `mojo-to-xch` unconditionally, regardless of which wallet type `wallet_id` actually refers to: [4](#0-3) 

`wallet_id` is hidden from the main confirmation display (`hide: true`), so the user never sees which wallet is being spent: [5](#0-4) 

`parseCommandDisplay` only provides enriched display logic for `chia_wallet.take_offer` and `chia_wallet.create_offer_for_ids`; it returns `undefined` for `chia_wallet.send_transaction`, leaving the wallet-type mismatch undetected: [6](#0-5) 

The confirmed params (including the attacker-supplied `wallet_id`) are passed directly to `sendCommand` after user approval, with no post-confirmation wallet-type check: [7](#0-6) 

---

### Impact Explanation

XCH uses 10¹² mojos per coin; CAT tokens use 10³ mojos per token. A dApp that supplies `wallet_id: 2` (a CAT wallet) and `amount: 1_000_000` causes:

- **Confirmation dialog shows**: `0.000001 XCH` (1,000,000 ÷ 10¹²)
- **Daemon actually executes**: send `1,000 CAT` (1,000,000 ÷ 10³) from the CAT wallet

The user approves a negligible-looking XCH amount but loses 1,000 CAT tokens. This is a direct, unauthorized asset transfer of the wrong token type and wrong magnitude — matching the **High** impact category: *"causes a user to approve… the wrong asset, identity, amount, destination, or status."*

---

### Likelihood Explanation

The attacker must control a dApp that the victim has paired and granted `chia_sendTransaction` permission. This is a "spending" category command that requires explicit user approval at pairing time. However:

1. The user grants a generic "send transaction" permission without understanding it applies to all wallet types.
2. The dApp can enumerate wallet IDs silently via `chia_getWallets` (which has `allowConfirmationBypass: true` and can be pre-approved without per-call confirmation).
3. Once the wallet ID of a CAT wallet is known, the dApp can craft the substitution attack at any time. [8](#0-7) 

---

### Recommendation

1. **Resolve `wallet_id` to its wallet type before display.** In the confirmation dialog for `chia_wallet.send_transaction`, look up the wallet type for the supplied `wallet_id` and display it explicitly (e.g., "Send from: CAT wallet — Duck Sauce"). Humanize `amount` using the correct unit for that wallet type (`mojo-to-cat` for CAT, `mojo-to-xch` for XCH).

2. **Restrict `wallet_id` to the standard wallet in the dApp schema.** Override `params` in the `chia_sendTransaction` dapp entry to exclude `wallet_id` entirely (relying on the default of `1`), or add an explicit allowlist check that rejects non-standard wallet IDs unless the user has explicitly granted CAT-spending permission.

3. **Remove `hide: true` from `wallet_id`** or replace it with a human-readable wallet name in the confirmation rows so the user can always see which wallet is being spent.

---

### Proof of Concept

1. Attacker operates a dApp that the victim has paired with `chia_sendTransaction` + `chia_getWallets` permissions.
2. dApp calls `chia_getWallets` (bypassed, no confirmation) to enumerate wallets; identifies `wallet_id: 2` as a CAT wallet holding 1,000 tokens.
3. dApp calls `chia_sendTransaction` with:
   ```json
   { "wallet_id": 2, "amount": 1000000, "fee": 0, "address": "attacker_address" }
   ```
4. Confirmation dialog renders: **"Send 0.000001 XCH to attacker_address"** — `wallet_id` is hidden, amount is humanized as XCH.
5. Victim approves, believing they are sending a negligible dust amount of XCH.
6. Daemon executes `send_transaction` from wallet 2 (CAT), transferring **1,000 CAT tokens** to the attacker's address. [1](#0-0) [9](#0-8) [10](#0-9)

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L131-177)
```typescript
  'chia_wallet.send_transaction': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Send Transaction' }),
    message: () => i18n._(/* i18n */ { id: 'Please carefully review and confirm this blockchain transaction.' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Send' }),
    params: [
      {
        name: 'amount',
        label: () => i18n._(/* i18n */ { id: 'Amount' }),
        type: 'bigint',
        humanize: 'mojo-to-xch',
      },
      {
        name: 'fee',
        label: () => i18n._(/* i18n */ { id: 'Fee' }),
        type: 'bigint',
        humanize: 'mojo-to-xch',
      },
      { name: 'address', label: () => i18n._(/* i18n */ { id: 'Address' }), type: 'string' },
      {
        name: 'wallet_id',
        label: () => i18n._(/* i18n */ { id: 'Wallet Id' }),
        type: 'number',
        hide: true,
      },
      {
        name: 'memos',
        label: () => i18n._(/* i18n */ { id: 'Memos' }),
        type: 'json',
        isOptional: true,
        hide: true,
      },
      {
        name: 'puzzle_decorator',
        label: () => i18n._(/* i18n */ { id: 'Puzzle Decorator' }),
        type: 'json',
        isOptional: true,
      },
    ],
    dapp: [
      {
        command: 'chia_sendTransaction',
        title: () => i18n._(/* i18n */ { id: 'Send Transaction' }),
        requiresSync: true,
        defaults: { wallet_id: 1 },
      },
    ],
  },
```

**File:** packages/gui/src/electron/commands/DappCommands.ts (L15-32)
```typescript
        const {
          title = commandSchema.title,
          message = commandSchema.message,
          confirmLabel = commandSchema.confirmLabel,
          params = [...commandSchema.params],
          destructive = commandSchema.destructive === true,
          ...rest
        } = dapp;

        DappCommands.set(command, {
          ...rest,
          commandId,
          title,
          message,
          confirmLabel,
          params,
          destructive,
        });
```

**File:** packages/gui/src/electron/commands/parseDappParams.ts (L8-38)
```typescript
export function parseDappParams(dappCommand: string, params: string): Record<string, unknown> {
  const dappCommandSchema = getDappCommandSchema(dappCommand);

  // snake-case before any field read so case-folding can't dodge the gate.
  const parsedParams = toSnakeCase(JSONbig({ useNativeBigInt: true }).parse(params), {
    deep: !dappCommandSchema.preserveNestedDataKeys,
  });
  const dappParams = dappCommandSchema.params;

  // fast searching of params
  const dappParamsMap = new Map<string, ParamSchema>();
  for (const param of dappParams) {
    dappParamsMap.set(param.name, param);
  }

  // remove fingerprint from params if it is not allowed for the dapp
  if ('fingerprint' in parsedParams && !dappParamsMap.has('fingerprint')) {
    delete parsedParams.fingerprint;
  }

  // add default values if they are not provided (aliases can use them)
  const nextParams = {
    ...parsedParams,
  };

  // validate via assert if all params are allowed for the dapp
  Object.keys(nextParams).forEach((key) => {
    if (!dappParamsMap.has(key)) {
      throw new Error(`param not allowed for dapp: ${key}`);
    }
  });
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L438-483)
```typescript
export async function parseCommandDisplay(command: string, params: Record<string, unknown>) {
  if (command === 'chia_wallet.take_offer') {
    if (!params.offer || typeof params.offer !== 'string') {
      throw new Error('Offer is not valid');
    }

    const offerSummary = await getOfferSummary(params.offer);
    if (!offerSummary || !offerSummary.summary || !offerSummary.success) {
      throw new Error('Offer is not valid');
    }

    const { summary } = offerSummary;

    const walletDelta = offerSummaryToWalletDelta(summary);
    const walletInfos = await getWalletInfos();
    const assetKinds = offerSummaryAssetKinds(summary);
    const royaltyPercentages = offerSummaryRoyaltyPercentages(summary);
    const fees = parseMojos(summary.fees);

    return {
      walletDelta: await walletDeltaToDisplay(walletDelta, walletInfos, assetKinds, royaltyPercentages, fees),
    };
  }

  if (command === 'chia_wallet.create_offer_for_ids') {
    if (!params.offer || !isPlainObject(params.offer)) {
      throw new Error('Offer is not valid');
    }

    if (params.driver_dict !== undefined && !isPlainObject(params.driver_dict)) {
      throw new Error('Driver Dict is not valid');
    }

    const walletDelta = createOfferToWalletDelta(params.offer);
    const walletInfos = await getWalletInfos();
    const driverDict = params.driver_dict ?? {};
    const assetKinds = createOfferAssetKinds(walletDelta, walletInfos, driverDict);
    const royaltyPercentages = createOfferRoyaltyPercentages(walletDelta, driverDict);

    return {
      walletDelta: await walletDeltaToDisplay(walletDelta, walletInfos, assetKinds, royaltyPercentages, undefined),
    };
  }

  return undefined;
}
```

**File:** packages/gui/src/electron/main.tsx (L290-300)
```typescript
        async (context) => {
          const { destination, command: chiaCommand } = parseCommandId(commandId);

          const response = dappCommandSchema.handler
            ? await dappCommandSchema.handler(parsedParams, {
                ...context,
                sendNotification: sendRendererNotification,
                canBypassCommand: (requestedCommand) =>
                  DappCommands.get(requestedCommand)?.allowConfirmationBypass === true,
              })
            : await sendCommand(chiaCommand, destination, parsedParams);
```

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L56-64)
```typescript
  // if command is bypassed return true
  if (pair.bypass.includes(command)) {
    return process(context);
  }

  const isAllowed = await confirm();
  if (isAllowed === true) {
    return process(context);
  }
```
