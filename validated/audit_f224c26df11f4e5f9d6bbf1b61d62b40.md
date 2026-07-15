The full execution path is now clear. Let me summarize the findings:

**`chia_full_node.push_tx` / `chia_pushTx` confirmation dialog:**

1. The command schema defines `spend_bundle` as `type: 'json'` with no special handling.
2. `humanizeParamValue` for `type: 'json'` calls `JSONBig.stringify(value, null, 2)` — raw serialization, no CLVM decoding.
3. `parseCommandDisplay` only handles `chia_wallet.take_offer` and `chia_wallet.create_offer_for_ids`; it returns `undefined` for `chia_full_node.push_tx`, so no `walletDelta` section is rendered.
4. The `Confirm` dialog renders the `spend_bundle` row as a raw JSON string with `puzzleReveal` as opaque hex.

---

### Title
Raw hex `puzzleReveal` display in `chia_pushTx` confirmation dialog prevents users from verifying spend destinations — (`packages/gui/src/electron/commands/Commands.ts`)

### Summary
The WalletConnect `chia_pushTx` command (`chia_full_node.push_tx`) presents the entire `spend_bundle` — including `puzzleReveal` CLVM programs — as a raw JSON blob in the confirmation dialog. No CLVM decoding, destination address extraction, or amount display is performed. A malicious dApp granted `chia_pushTx` can craft a `SpendBundle` that sends funds to an attacker-controlled address; the confirmation dialog gives the user no human-readable information about where funds are going.

### Finding Description

The command is registered in `Commands.ts`:

```ts
'chia_full_node.push_tx': {
  params: [{ name: 'spend_bundle', label: 'Spend Bundle', type: 'json' }],
  ...
}
``` [1](#0-0) 

The `type: 'json'` path in `humanizeParamValue` serializes the value verbatim:

```ts
case 'json':
  return JSONBig.stringify(value, null, 2);
``` [2](#0-1) 

`parseCommandDisplay` only enriches `take_offer` and `create_offer_for_ids`; it returns `undefined` for `chia_full_node.push_tx`, so no `walletDelta` section is shown: [3](#0-2) 

The `Confirm` dialog renders the resulting row value as plain text: [4](#0-3) 

The `SpendBundle` type confirms `puzzleReveal` is a raw hex string with no decoding layer: [5](#0-4) 

### Impact Explanation
A dApp granted `chia_pushTx` can submit a `SpendBundle` whose `puzzleReveal` encodes a CLVM program that creates outputs to attacker-controlled addresses. The confirmation dialog shows only the raw hex string — e.g., `"ff02ff04ffff04ff02ffff04ff05ff80808080"` — with no decoded destination address or amount. The user has no way to distinguish a legitimate spend from a malicious one and will approve based on the dApp's name/reputation alone. Upon approval, the daemon executes the spend and funds are transferred to the attacker.

### Likelihood Explanation
Any dApp that has been granted `chia_pushTx` permission can exploit this. The permission itself requires a one-time user grant, but once granted, every subsequent `chia_pushTx` call relies solely on the unreadable confirmation dialog as the guard. A dApp that was initially trusted (e.g., a legitimate DEX) but later compromised, or a dApp that social-engineers the initial permission grant, can exploit this on every subsequent call.

### Recommendation
- For `chia_full_node.push_tx`, decode each `coinSpend.puzzleReveal` from CLVM serialization and extract `CREATE_COIN` conditions to display destination addresses and amounts in the confirmation dialog.
- At minimum, display a prominent warning that `puzzleReveal` cannot be decoded and the destination addresses are unknown, and require an explicit acknowledgment before allowing confirmation.
- Consider whether `chia_pushTx` should be a grantable WalletConnect permission at all, given that it bypasses all wallet-level transaction construction and validation.

### Proof of Concept
1. Connect a malicious dApp via WalletConnect and obtain `chia_pushTx` permission (one-time social engineering).
2. Craft a `SpendBundle` with a `puzzleReveal` that is a valid CLVM program encoding `(CREATE_COIN attacker_puzzle_hash amount)`.
3. Call `chia_pushTx` with this bundle.
4. The confirmation dialog shows `"Spend Bundle": { "coin_spends": [{ "puzzle_reveal": "ff02ff04...<attacker hex>...", ... }] }`.
5. The user sees only opaque hex — no destination address, no amount — and clicks "Push".
6. The daemon executes the spend; funds arrive at the attacker address.
7. Assert: the dialog rendered no decoded address or amount, and no warning about undecodable CLVM was shown.

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L694-706)
```typescript
  'chia_full_node.push_tx': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Push Transaction' }),
    message: () => i18n._(/* i18n */ { id: 'Please carefully review and confirm pushing this transaction.' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Push' }),
    params: [{ name: 'spend_bundle', label: () => i18n._(/* i18n */ { id: 'Spend Bundle' }), type: 'json' }],
    dapp: [
      {
        command: 'chia_pushTx',
        title: () => i18n._(/* i18n */ { id: 'Push Transaction' }),
        message: () => i18n._(/* i18n */ { id: 'Push a spend bundle (transaction) to the blockchain' }),
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

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L383-392)
```typescript
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

**File:** packages/api/src/@types/SpendBundle.ts (L4-8)
```typescript
type CoinSpends = {
  coin: Coin;
  puzzleReveal: string;
  solution: string;
};
```
