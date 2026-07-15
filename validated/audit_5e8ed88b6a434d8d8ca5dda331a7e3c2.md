The code evidence is clear. Let me verify the `parseCommandDisplay` function to confirm there's no enrichment for `cancel_offer`.

### Title
WalletConnect `chia_cancelOffer` Approval Dialog Exposes Only Opaque `trade_id` Hash, Enabling Malicious dApp to Silently Cancel Any Wallet Offer — (`packages/gui/src/electron/commands/Commands.ts`)

---

### Summary

A WalletConnect dApp that has been granted the `chia_cancelOffer` permission can send a `chia_cancelOffer` request with any `trade_id` belonging to the currently logged-in wallet. The GUI approval dialog shows only the raw `trade_id` hex string and fee — no offer asset details, amounts, or status — because `parseCommandDisplay` has no handler for `chia_wallet.cancel_offer`. The user cannot make an informed decision about which offer is being cancelled. The `secure` flag is silently hardcoded to `true` (on-chain cancellation transaction), making the action irreversible and fee-bearing.

---

### Finding Description

**1. `secure` hardcoded to `true`, hidden from the user**

In `Commands.ts`, the `chia_cancelOffer` dapp entry overrides the displayed params to exclude `secure`, while injecting it as a default: [1](#0-0) 

`parseDappParams` applies this default unconditionally when the dApp omits `secure`: [2](#0-1) 

**2. Approval dialog shows only an opaque hex hash**

The dapp `params` list for `chia_cancelOffer` contains only `trade_id` (a raw hex string) and `fee`. There is no enrichment step. `parseCommandDisplay` handles `take_offer` and `create_offer_for_ids` with full asset/amount resolution, but has no case for `cancel_offer` and returns `undefined`: [3](#0-2) 

The `display` passed to the confirmation dialog is therefore `undefined` for `cancel_offer`, leaving the user with only the raw `trade_id` string. [4](#0-3) 

**3. No ownership/existence check on `trade_id` at the GUI layer**

`parseDappParams` performs only type validation and default injection — it does not verify that the supplied `trade_id` corresponds to an existing, pending offer in the wallet before presenting the approval dialog. [5](#0-4) 

**4. Execution path after approval**

Because `chia_cancelOffer` has no custom `handler`, approval causes `sendCommand('cancel_offer', 'chia_wallet', parsedParams)` to be called directly with the attacker-supplied `trade_id` and `secure: true`: [6](#0-5) 

---

### Impact Explanation

A malicious dApp granted `chia_cancelOffer` permission can:

1. Obtain the victim's `trade_id` values (via `chia_getAllOffers` if also granted, or by observing the mempool/blockchain where offer coins are visible).
2. Send `chia_cancelOffer` with a targeted `trade_id` at a strategically chosen moment (e.g., when a profitable offer is about to be filled).
3. The user sees only `"Trade Id: 0xabc…"` and `"Fee: X XCH"` — no indication of what assets or amounts are involved.
4. Upon approval, `cancel_offer` is called with `secure: true`, submitting an irreversible on-chain cancellation transaction.

This directly fits: **"WalletConnect state that causes a user to approve the wrong asset/status"** — the user cannot distinguish which offer is being cancelled, enabling front-running of profitable trades or targeted disruption of pending offers.

---

### Likelihood Explanation

- Requires an established WalletConnect session where the user has granted `chia_cancelOffer` to the dApp. This is a realistic precondition for any dApp that legitimately manages offers.
- `trade_id` values are not secret — they are derivable from the blockchain (offer coin IDs are public) or from `chia_getAllOffers` if that permission is also granted.
- The attack requires only one user approval click on a dialog that provides no meaningful context.

---

### Recommendation

In `parseCommandDisplay`, add a `chia_wallet.cancel_offer` branch that calls `get_offer` (using `trade_id`) to fetch and display the offer's asset details, amounts, and status before presenting the approval dialog — mirroring the enrichment already done for `take_offer` and `create_offer_for_ids`. This gives the user the context needed to make an informed decision. [7](#0-6) 

---

### Proof of Concept

1. Establish a WalletConnect session granting `chia_cancelOffer` (and optionally `chia_getAllOffers`) to a test dApp.
2. Create a pending offer in the wallet (e.g., offer 1 XCH for a CAT). Note the `trade_id`.
3. From the dApp, send:
   ```json
   { "command": "chia_cancelOffer", "params": { "tradeId": "<victim_trade_id>", "fee": 0 } }
   ```
4. Observe the approval dialog: it shows only `"Trade Id: <hex>"` and `"Fee: 0 XCH"` — no asset names, amounts, or offer status.
5. Click "Proceed". Verify via RPC that `cancel_offer` was called with `secure: true` and the offer is cancelled on-chain.
6. Assert that the user had no way to distinguish this offer from any other offer by `trade_id` alone.

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L261-274)
```typescript
    dapp: [
      {
        command: 'chia_cancelOffer',
        title: () => i18n._(/* i18n */ { id: 'Cancel Offer' }),
        defaults: {
          secure: true,
        },
        // override list of params to hide secure
        params: [
          { name: 'trade_id', label: () => i18n._(/* i18n */ { id: 'Trade Id' }), type: 'string' },
          { name: 'fee', label: () => i18n._(/* i18n */ { id: 'Fee' }), type: 'bigint', humanize: 'mojo-to-xch' },
        ],
      },
    ],
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

**File:** packages/gui/src/electron/commands/parseDappParams.ts (L40-48)
```typescript
  // apply all default values if they are not provided (aliases can use them)
  // devs can apply default values that are not in params list
  if (dappCommandSchema.defaults) {
    for (const [key, value] of Object.entries(dappCommandSchema.defaults)) {
      if (nextParams[key] === undefined) {
        nextParams[key] = value;
      }
    }
  }
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L438-482)
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

**File:** packages/gui/src/electron/main.tsx (L329-344)
```typescript
          const display = await parseCommandDisplay(commandId, parsedParams);

          const confirmResult = await openReactDialog<ConfirmDialogResult, ConfirmProps>(
            mainWindow,
            Confirm,
            {
              networkPrefix,
              command: commandId,
              data: parsedParams,
              title,
              message,
              confirmLabel,
              destructive,
              rows,
              pair,
              display,
```
