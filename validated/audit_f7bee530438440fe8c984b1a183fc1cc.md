### Title
WalletConnect `chia_sendTransaction` Hides `wallet_id` Parameter, Enabling Malicious dApp to Spoof Asset Type in Confirmation Dialog - (File: packages/gui/src/electron/commands/Commands.ts)

### Summary
A malicious WalletConnect dApp with `chia_sendTransaction` permission can supply any `wallet_id` in its request. Because `wallet_id` is marked `hide: true` in the confirmation-dialog schema and the `amount` field is always humanized as XCH (mojo-to-xch), the user sees a dialog that says "Send X XCH" while the actual RPC call targets a CAT wallet. This is a direct GUI analog of the `bps()` calldata-injection bug: the displayed asset context and the executed asset context are decoupled, and the attacker controls the discrepancy.

### Finding Description

In `Commands.ts`, the `chia_wallet.send_transaction` command schema declares `wallet_id` with `hide: true`:

```typescript
'chia_wallet.send_transaction': {
  params: [
    { name: 'amount', type: 'bigint', humanize: 'mojo-to-xch' },
    { name: 'fee',    type: 'bigint', humanize: 'mojo-to-xch' },
    { name: 'address', type: 'string' },
    { name: 'wallet_id', type: 'number', hide: true },   // ← hidden
    ...
  ],
  dapp: [{
    command: 'chia_sendTransaction',
    requiresSync: true,
    defaults: { wallet_id: 1 },   // default = XCH, but overridable
  }],
},
``` [1](#0-0) 

The `hide: true` flag excludes `wallet_id` from the rows rendered in the `Confirm` dialog. The `Confirm` component only shows a collapsed "Raw data" section that most users never expand: [2](#0-1) 

The `parseDappParams` allowlist **does** permit the dApp to override `wallet_id`. The existing test suite explicitly confirms this:

```typescript
// parseDappParams.test.ts – dApp can override wallet_id
parseDappParams('chia_sendTransaction', serialize({
  amount: '1', fee: '0', address: 'txch1address',
  walletId: 2,   // overrides default wallet_id: 1
}))
// → { wallet_id: 2, ... }
``` [3](#0-2) 

Because `parseCommandDisplay` returns `undefined` for `chia_wallet.send_transaction` (it only enriches `take_offer` and `create_offer_for_ids`), no wallet-type-aware display is generated: [4](#0-3) 

The `dispatchAsPair` handler in `main.tsx` passes `parsedParams` (which already contains the attacker-supplied `wallet_id`) directly to both the confirmation dialog and the backend RPC call, with no reconciliation between the two: [5](#0-4) 

### Impact Explanation

A malicious dApp can silently enumerate wallets via `chia_getWallets` (which carries `allowConfirmationBypass: true` and requires no user confirmation), identify a CAT wallet with a large balance, then issue `chia_sendTransaction` targeting that wallet. The confirmation dialog will display the mojo amount converted to XCH (e.g., "Send 0.001 XCH") while the actual RPC call executes against the CAT wallet, transferring CAT tokens to the attacker's address. The user approves the wrong asset transfer without any visible indication of the wallet type or asset being spent.

This matches the **High** impact class: *"WalletConnect state that causes a user to approve … the wrong asset, identity, amount … or status."*

### Likelihood Explanation

The attacker must be a connected WalletConnect dApp that the user has already granted `chia_sendTransaction` permission. This is a realistic threat model: a dApp that legitimately needs to send XCH can abuse the same permission to send CAT tokens. The `chia_getWallets` enumeration step requires no additional user approval.

### Recommendation

1. **Remove `wallet_id` from the dApp-facing allowlist** for `chia_sendTransaction`, locking it to `wallet_id: 1` (XCH). CAT transfers should require a separate, explicitly named command.
2. **Or**, if multi-wallet support is intentional, remove `hide: true` from `wallet_id` and display the resolved wallet name/type (e.g., "Wallet: Stably USD (CAT)") prominently in the confirmation dialog.
3. **Or**, derive the `humanize` conversion from the actual wallet type rather than hardcoding `mojo-to-xch`, so the displayed amount at minimum reflects the correct denomination.

### Proof of Concept

```javascript
// Step 1: enumerate wallets silently (no confirmation required)
const wallets = await walletConnectClient.request({
  topic, chainId,
  request: { method: 'chia_getWallets', params: { fingerprint } }
});

// Step 2: find a high-value CAT wallet
const catWallet = wallets.find(w => w.type === 'cat_wallet');

// Step 3: send chia_sendTransaction targeting the CAT wallet
// Dialog shows: "Send 0.001 XCH to xch1attacker…"
// Actual RPC:   send_transaction(wallet_id=catWallet.id, amount=1000, …)
await walletConnectClient.request({
  topic, chainId,
  request: {
    method: 'chia_sendTransaction',
    params: {
      fingerprint,
      walletId: catWallet.id,   // overrides default wallet_id:1
      amount: '1000',           // displayed as 0.000001 XCH; actually 1 CAT
      fee: '0',
      address: 'xch1attacker…',
    }
  }
});
```

The user sees a confirmation dialog showing an XCH amount with no wallet-type indicator. Upon approval, the Chia wallet daemon executes `send_transaction` against the CAT wallet, transferring CAT tokens to the attacker.

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

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L383-400)
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

          {hasData && (
            <Collapsible title="Raw data">
              <pre className="m-0 text-xs font-mono leading-relaxed break-all whitespace-pre-wrap text-chia-text-secondary">
                {JSON.stringify(data, (_, v) => (typeof v === 'bigint' ? String(v) : v), 2)}
              </pre>
            </Collapsible>
          )}
```

**File:** packages/gui/src/electron/commands/parseDappParams.test.ts (L46-76)
```typescript
    it('applies schema defaults only when the dapp omitted the value', () => {
      expect(
        parseDappParams(
          'chia_sendTransaction',
          serialize({
            amount: '1',
            fee: '0',
            address: 'txch1address',
          }),
        ),
      ).toMatchObject({
        amount: 1n,
        fee: 0n,
        address: 'txch1address',
        wallet_id: 1,
      });

      expect(
        parseDappParams(
          'chia_sendTransaction',
          serialize({
            amount: '1',
            fee: '0',
            address: 'txch1address',
            walletId: 2,
          }),
        ),
      ).toMatchObject({
        wallet_id: 2,
      });
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

**File:** packages/gui/src/electron/main.tsx (L282-366)
```typescript
      const parsedParams = parseDappParams(command, params);

      // verify all permissions and execute command after user confirmation
      const result = await dispatchPairRequest(
        topic,
        command,
        parsedParams,
        // process the command
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

          const transformedResponse = dappCommandSchema.transform ? dappCommandSchema.transform(response) : response;

          // dapp is sending back camelCase response
          const camelCaseResponse = toCamelCase(transformedResponse as Record<string, unknown>, {
            deep: !dappCommandSchema.preserveNestedDataKeys,
          });

          return dappCommandSchema.handler ? camelCaseResponse : { data: camelCaseResponse };
        },
        // show the confirm dialog to the user
        async () => {
          // humanize all data from command
          const { title, message, confirmLabel, destructive, rows } = await humanizeDappCommand(
            command,
            parsedParams,
            networkPrefix,
          );

          const pair = findPair(topic);
          if (!pair) {
            throw new WcError(`Pair not found`, WcErrorCode.USER_REJECTED);
          }

          if (!mainWindow) {
            throw new WcError('mainWindow is empty', WcErrorCode.INTERNAL_ERROR);
          }

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
              showBypassToggle: dappCommandSchema.allowConfirmationBypass === true,
            },
            {
              title,
              width: 640,
              height: 600,
            },
          );

          if (confirmResult && confirmResult.isAllowed === true) {
            if (confirmResult.rememberBypass && dappCommandSchema.allowConfirmationBypass === true) {
              addBypassCommand(topic, command);
            }

            return true;
          }

          throw new WcError('Operation cancelled by user', WcErrorCode.USER_REJECTED);
        },
      );

      return JSONbig.stringify(result);
```
