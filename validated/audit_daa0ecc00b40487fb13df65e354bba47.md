Now I have a complete picture. Let me verify the Confirm.tsx rendering of `type: 'json'` params to confirm the raw JSON display.

The code evidence is conclusive. Here is the full analysis:

---

### Title
WalletConnect `chia_takeDataLayerOffer` Approval Dialog Renders Offer as Raw JSON Blob, Preventing Meaningful User Review — (`packages/gui/src/electron/commands/Commands.ts`, `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary

The WalletConnect approval dialog for `chia_data_layer.take_offer` displays the entire `offer` parameter as a raw `JSON.stringify` blob. The `parseCommandDisplay` function — which is the only mechanism for injecting human-readable summaries into the `Confirm` dialog — has no case for `chia_data_layer.take_offer`. A connected WalletConnect dApp can therefore craft any offer object it chooses; the user sees an opaque JSON blob and has no way to verify which store IDs will be updated or what the new roots will be before clicking Accept.

### Finding Description

**1. Command definition — `offer` typed as `'json'`**

In `Commands.ts`, the `chia_data_layer.take_offer` entry declares the `offer` parameter with `type: 'json'`: [1](#0-0) 

**2. `humanizeParamValue` renders `type: 'json'` as a raw stringify**

`humanizeParamValue.ts` converts every `type: 'json'` param to `JSONBig.stringify(value, null, 2)` — a pretty-printed but completely uninterpreted blob: [2](#0-1) 

**3. `parseCommandDisplay` has no case for `chia_data_layer.take_offer`**

`parseCommandDisplay` is the only hook that can inject a structured `ConfirmDisplay` (with `walletDelta` or equivalent) into the dialog. It handles `chia_wallet.take_offer` and `chia_wallet.create_offer_for_ids`, but returns `undefined` for every other command, including `chia_data_layer.take_offer`: [3](#0-2) 

**4. `main.tsx` passes `display` (which is `undefined`) to `Confirm`**

Both the WalletConnect dApp path and the renderer-intercept path call `parseCommandDisplay` and forward the result as `display`: [4](#0-3) [5](#0-4) 

**5. `Confirm.tsx` only renders `WalletDeltaSection` when `display?.walletDelta` is present**

Because `display` is `undefined` for `chia_data_layer.take_offer`, the structured offer section is never rendered. The dialog falls through to the raw `rows` section, which shows the JSON blob: [6](#0-5) 

**6. `DataLayerOfferViewer` exists but is never wired into the WalletConnect approval path**

The component that renders store IDs, new roots, and dependency proofs in a human-readable way is used in the normal offer-import flow (`OfferBuilderViewer`, `OfferBuilderViewerDialog`), but is completely absent from the WalletConnect approval dialog: [7](#0-6) 

**7. `chia_data_layer.take_offer` is in `BlockedCommands` — approval IS required**

The command is not auto-approved; it always triggers the `Confirm` dialog: [8](#0-7) 

### Impact Explanation

A connected WalletConnect dApp can send `chia_takeDataLayerOffer` with any crafted `offer` object — pointing to arbitrary store IDs and new roots — and the user's approval dialog will show only an unreadable JSON blob. The user cannot verify:
- Which store IDs will have their roots updated
- What the new root hashes will be
- What inclusions/dependencies are required

This directly enables unauthorized DataLayer store-root transitions approved without meaningful user review, fitting the **High** impact category: *"Corruption, spoofing, or unsafe trust of… DataLayer… WalletConnect state that causes a user to approve… the wrong asset, identity, amount, destination, or status."*

### Likelihood Explanation

The attacker must already be a connected WalletConnect dApp (pairing requires user approval once). After pairing, sending a crafted `chia_takeDataLayerOffer` request is trivial — no additional privileges are needed. The gap is structural: `parseCommandDisplay` simply has no branch for `chia_data_layer.take_offer`, so every invocation of this command via WalletConnect is affected.

### Recommendation

Add a `chia_data_layer.take_offer` branch to `parseCommandDisplay` that:
1. Extracts the bech32 `offer` string from `params.offer.offer`
2. Calls the DataLayer offer-summary RPC (or reuses the existing `getOfferSummary` / DataLayer equivalent)
3. Returns a structured display object containing the store IDs and new roots

Alternatively, extend `ConfirmDisplay` with a `dataLayerOfferSummary` field and render `DataLayerOfferViewer` inside `Confirm.tsx` when that field is present — mirroring exactly what `OfferBuilderViewerDialog` already does: [9](#0-8) 

### Proof of Concept

1. Pair a WalletConnect dApp with the Chia GUI.
2. Send the following WalletConnect request:
   ```json
   {
     "method": "chia_takeDataLayerOffer",
     "params": {
       "offer": {
         "tradeId": "deadbeef...",
         "offer": "offer1qpzry9x8gf2tvdw0s3jn54khce6mua7l...",
         "taker": { "storeId": "<attacker-controlled-store>", "inclusions": [] },
         "maker": { "storeId": "<victim-store>", "inclusions": [] }
       }
     }
   }
   ```
3. Observe the approval dialog: the `Offer` field shows a raw JSON blob. No store IDs or new roots are rendered in human-readable form.
4. Assert: the dialog does **not** render parsed store IDs or new root hashes (contrast with `chia_wallet.take_offer`, which renders a full `WalletDeltaSection`).
5. Click Accept — `takeDataLayerOffer` RPC is called with the attacker-crafted offer.

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L1409-1429)
```typescript
  'chia_data_layer.take_offer': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Take DataLayer Offer' }),
    message: () => i18n._(/* i18n */ { id: 'Please carefully review and confirm taking this DataLayer offer.' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Accept' }),
    params: [
      { name: 'offer', label: () => i18n._(/* i18n */ { id: 'Offer' }), type: 'json' },
      {
        name: 'fee',
        label: () => i18n._(/* i18n */ { id: 'Fee' }),
        type: 'bigint',
        humanize: 'mojo-to-xch',
        isOptional: true,
      },
    ],
    dapp: [
      {
        command: 'chia_takeDataLayerOffer',
        title: () => i18n._(/* i18n */ { id: 'Take DataLayer Offer' }),
      },
    ],
  },
```

**File:** packages/gui/src/electron/commands/humanizeParamValue.ts (L64-69)
```typescript
    case 'json':
      try {
        return JSONBig.stringify(value, null, 2);
      } catch {
        return String(value);
      }
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

**File:** packages/gui/src/electron/main.tsx (L825-840)
```typescript
        const display = await parseCommandDisplay(commandId, commandData);

        const confirmResult = await openReactDialog<ConfirmDialogResult, ConfirmProps>(
          mainWindow,
          Confirm,
          {
            networkPrefix,
            command: commandId,
            data: commandData,
            title,
            message,
            confirmLabel,
            destructive,
            rows,
            display,
          },
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L381-392)
```typescript
          {walletDelta && <WalletDeltaSection walletDelta={walletDelta} networkPrefix={networkPrefix} />}

          {rows.length > 0 && (
            <section className="rounded-xl border border-chia-border bg-chia-card overflow-hidden divide-y divide-chia-border">
              {rows.map(({ field, label, value }) => (
                <div className="px-5 py-2.5" key={field}>
                  <div className="text-xs font-semibold uppercase tracking-wider text-chia-text-muted">{label}</div>
                  <div className="mt-0.5 text-sm font-medium break-all whitespace-pre-wrap text-chia-text">{value}</div>
                </div>
              ))}
            </section>
          )}
```

**File:** packages/gui/src/components/offers2/DataLayerOfferViewer.tsx (L143-182)
```typescript
export default function DataLayerOfferViewer(props: DataLayerOfferViewerProps) {
  const { summary } = props;

  return (
    <Flex flexDirection="column" gap={3}>
      <Typography variant="h6">
        <Trans>Data Layer Offer</Trans>
      </Typography>
      <Typography variant="body2" color="textSecondary">
        <Trans>
          This offer proposes updates to Data Layer store roots. Accepting it will transition the listed stores to new
          roots. Dependencies specify values that must be proven to exist in other stores before acceptance.
        </Trans>
      </Typography>

      <Divider />

      <Box>
        <Flex alignItems="center" gap={1} sx={{ mb: 1.5 }}>
          <StorageIcon fontSize="small" color="primary" />
          <Typography variant="subtitle1">
            <Trans>Offered Store Updates ({summary.offered.length})</Trans>
          </Typography>
        </Flex>
        <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
          <Trans>These stores will have their roots updated to the specified values.</Trans>
        </Typography>
        <Flex flexDirection="column" gap={2}>
          {summary.offered.map((entry, i) => (
            <StoreUpdateCard key={entry.launcherId} entry={entry} index={i} />
          ))}
        </Flex>
      </Box>

      <Divider />

      <RequiredProofsTable entries={summary.offered} />
    </Flex>
  );
}
```

**File:** packages/gui/src/constants/BlockedCommands.ts (L46-46)
```typescript
  'chia_data_layer.take_offer',
```

**File:** packages/gui/src/components/offers2/OfferBuilderViewerDialog.tsx (L64-65)
```typescript
        ) : data && isDataLayerOfferSummary(data.summary) ? (
          <DataLayerOfferViewer summary={data.summary as DataLayerOfferSummary} />
```
