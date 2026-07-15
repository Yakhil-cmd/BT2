### Title
WalletConnect `chia_sendTransaction` Accepts Dapp-Supplied `wallet_id` Without Type Validation, Hidden from Confirmation Dialog — (File: `packages/gui/src/electron/commands/Commands.ts`)

### Summary

The `chia_sendTransaction` WalletConnect command accepts a dapp-controlled `wallet_id` parameter without verifying it corresponds to the standard (XCH) wallet. The parameter is marked `hide: true` in the confirmation schema, so it is omitted from the main confirmation dialog shown to the user. The amount is always humanized as `mojo-to-xch` regardless of the actual wallet type. A malicious dapp with `chia_sendTransaction` permission can substitute a CAT wallet ID, causing the user to approve what appears to be an XCH send while actually spending CAT tokens from a different wallet.

### Finding Description

In `Commands.ts`, the `chia_wallet.send_transaction` command schema defines `wallet_id` as a parameter with `hide: true`:

```ts
{ name: 'wallet_id', label: () => i18n._({ id: 'Wallet Id' }), type: 'number', hide: true },
```

The dapp-facing command `chia_sendTransaction` sets a default of `wallet_id: 1` but does **not** lock the value — the dapp may override it:

```ts
dapp: [{ command: 'chia_sendTransaction', requiresSync: true, defaults: { wallet_id: 1 } }],
```

The `parseDappParams` test suite explicitly confirms that a dapp-supplied `walletId: 2` is accepted and passed through as `wallet_id: 2`:

```ts
parseDappParams('chia_sendTransaction', serialize({ amount: '1', fee: '0', address: '...', walletId: 2 }))
// → { wallet_id: 2, ... }
```

Because `wallet_id` is `hide: true`, the confirmation dialog shown to the user omits it entirely. The `amount` field is always humanized via `mojo-to-xch`, so the user sees an XCH amount regardless of which wallet is actually being spent. There is no GUI-layer check that the supplied `wallet_id` belongs to a standard wallet (type `STANDARD_WALLET`). The `dispatchPairRequest` authorization layer validates fingerprint, command allowlist, and network — but performs no wallet-type or wallet-ownership check on the `wallet_id` value inside the params.

### Impact Explanation

A dapp that has been granted `chia_sendTransaction` permission can supply a CAT wallet ID (e.g., `wallet_id: 3`). The user's confirmation dialog shows:

- **Amount**: `X XCH` (mojo-to-xch humanization applied to what are actually CAT mojos)
- **Fee**: `Y XCH`
- **Address**: attacker-controlled destination

The user approves believing they are sending XCH. The daemon executes `send_transaction` against the CAT wallet, spending CAT tokens. Because 1 CAT = 1,000 mojos while 1 XCH = 1,000,000,000,000 mojos, the displayed amount and the actual CAT amount are wildly mismatched — a dapp requesting `amount: 1_000_000_000_000` shows "1 XCH" but spends 1,000,000,000 CAT. This is an unauthorized transfer of CAT assets caused by WalletConnect state spoofing that causes the user to approve the wrong asset type and amount.

### Likelihood Explanation

The attacker must be a dapp that the user has connected to via WalletConnect and granted `chia_sendTransaction` permission. This is a realistic scenario: users routinely grant this permission to DEXes and DeFi dapps. The attack requires no additional privileges, no key compromise, and no cryptographic break. The malicious dapp simply substitutes a different `wallet_id` in its RPC call.

### Recommendation

1. In `parseDappParams` or the `chia_sendTransaction` dapp command definition, validate that the supplied `wallet_id` corresponds to a `STANDARD_WALLET` type by querying `get_wallets` and cross-checking the type before dispatching.
2. Alternatively, strip `wallet_id` from dapp-supplied params for `chia_sendTransaction` and always inject the default (`1`) server-side, preventing dapps from overriding it.
3. Remove `hide: true` from `wallet_id` in the confirmation dialog so users can see which wallet is being spent, regardless of the above fix.

### Proof of Concept

1. User connects to a malicious dapp via WalletConnect and grants `chia_sendTransaction` permission.
2. Dapp sends `chia_sendTransaction` with `{ walletId: 3, amount: "1000000000000", fee: "0", address: "<attacker>" }` where wallet ID 3 is the user's CAT wallet.
3. `parseDappParams` accepts `wallet_id: 3` (confirmed by test at line 63–75 of `parseDappParams.test.ts`).
4. `dispatchPairRequest` validates fingerprint and command allowlist — no wallet-type check occurs.
5. Confirmation dialog shows **"Send 1 XCH to `<attacker>`"** — `wallet_id` is hidden (`hide: true`, line 153 of `Commands.ts`).
6. User approves. Daemon executes `send_transaction` on the CAT wallet, spending 1,000,000,000 CAT to the attacker.

---

**Key code references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L149-176)
```typescript
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
```

**File:** packages/gui/src/electron/commands/parseDappParams.test.ts (L63-76)
```typescript
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

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L28-54)
```typescript
  // verify if the command is allowed for this pair
  if (!pair.commands.includes(command)) {
    throw new WcError(`Command not allowed for this pair.`, WcErrorCode.UNAUTHORIZED_METHOD);
  }

  const { fingerprint } = params;

  // verify if the network is the same as the pair's network
  if (isMainnetValue !== pair.mainnet) {
    throw new WcError(`Network mismatch`, WcErrorCode.UNSUPPORTED_CHAINS);
  }

  // verify if the requested fingerprint is allowed for this pair
  const requestedFingerprint = fingerprint ?? loggedInFingerprint;
  if (typeof requestedFingerprint !== 'number' || !requestedFingerprint || requestedFingerprint !== pair.fingerprint) {
    throw new WcError(`Fingerprint not allowed for this command`, WcErrorCode.UNAUTHORIZED_METHOD);
  }

  const context = {
    pair,
    fingerprint: requestedFingerprint,
  };

  // Dapps may not switch the active key for an existing pair.
  if (fingerprint !== undefined && fingerprint !== loggedInFingerprint) {
    throw new WcError(`Fingerprint not allowed for this command`, WcErrorCode.UNAUTHORIZED_METHOD);
  }
```

**File:** packages/gui/src/electron/main.tsx (L282-300)
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
```
