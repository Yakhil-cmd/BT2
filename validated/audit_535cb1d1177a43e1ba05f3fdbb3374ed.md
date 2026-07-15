### Title
Dapp-Injected `extra_conditions` in WalletConnect Offer Commands Bypasses Intended Parameter Restrictions — (File: `packages/gui/src/electron/commands/Commands.ts`)

### Summary
The `chia_createOfferForIds` and `chia_takeOffer` WalletConnect dapp commands expose `extra_conditions` (and `coin_ids`) to an unprivileged dapp even though these parameters were not intended to be dapp-accessible. The `parseDappParams` allowlist check validates params against the full parent command schema without filtering by the `dappAllowed` annotation, allowing a malicious dapp to inject arbitrary CLVM conditions into offer creation and acceptance calls that the user cannot meaningfully evaluate in the confirmation dialog.

### Finding Description

**Step 1 — Schema definition exposes unintended params to dapps.**

In `Commands.ts`, the parent command `chia_wallet.create_offer_for_ids` declares `extra_conditions`, `coin_ids`, and `allow_unsynced` as optional params. Only `offer_only` carries `dappAllowed: true`. The developer left an explicit TODO acknowledging these params were not reviewed for dapp use: [1](#0-0) 

The dapp command `chia_createOfferForIds` is defined without overriding `params`, so it inherits the full parent param list including `extra_conditions` and `coin_ids`: [2](#0-1) 

Similarly, `chia_takeOffer` exposes `extra_conditions` to dapps: [3](#0-2) 

**Step 2 — `parseDappParams` allowlist does not filter by `dappAllowed`.**

`parseDappParams` builds its allowlist from every param in the schema and rejects only keys absent from that map. There is no check for `dappAllowed`: [4](#0-3) 

The `ParamSchema` type itself does not declare `dappAllowed`, confirming it is an unused annotation with no enforcement in the validation path: [5](#0-4) 

**Step 3 — Injected conditions flow directly to the daemon.**

`WalletService.createOfferForIds` passes `extra_conditions` and `coin_ids` verbatim to the `create_offer_for_ids` RPC call: [6](#0-5) 

**Step 4 — WalletConnect session request delivers dapp-controlled params to the command processor.**

The session request handler extracts `method` and `params` from the dapp's WalletConnect message and passes them through to `process()` without stripping undeclared fields: [7](#0-6) 

`useWalletConnectCommand` then forwards the full param object (minus only `waitForConfirmation`) to `dispatchAsPair`: [8](#0-7) 

### Impact Explanation

A dapp granted `chia_createOfferForIds` permission can inject arbitrary CLVM conditions via `extra_conditions`. For example, injecting `[["51", "<attacker_address>", "1000000000000"]]` adds a `CREATE_COIN` condition that sends 1 XCH to the attacker as part of the offer spend bundle. The user sees this in the confirmation dialog only as raw JSON of type `json` — opaque CLVM opcodes that a non-technical user cannot evaluate. The user approves what appears to be a normal offer but unknowingly authorizes an additional fund transfer to the attacker. This satisfies the **High** criterion: WalletConnect state causes a user to approve the wrong amount/destination.

### Likelihood Explanation

Any dapp that has been granted `chia_createOfferForIds` or `chia_takeOffer` permission (a spending-class permission the user explicitly grants at pairing time) can immediately exploit this. No additional privileges, key leakage, or host compromise are required. The attacker controls the WalletConnect session request payload entirely.

### Recommendation

1. **Enforce `dappAllowed` in `parseDappParams`**: Filter `dappParams` to only include entries where `dappAllowed === true` before building `dappParamsMap`, or add `dappAllowed` to `ParamSchema` and enforce it.
2. **Override `params` in the dapp definition**: The `chia_createOfferForIds` dapp entry should explicitly declare only the params dapps are permitted to supply, as `chia_cancelOffer` already does.
3. **Remove or strip `extra_conditions` and `coin_ids` from the dapp-facing schema** until they have been reviewed for dapp use (the existing TODO confirms this review has not occurred).

### Proof of Concept

A malicious dapp with `chia_createOfferForIds` permission sends the following WalletConnect session request:

```json
{
  "method": "chia_createOfferForIds",
  "params": {
    "fingerprint": 123456,
    "offer": { "1": -100000000000 },
    "driver_dict": {},
    "fee": "0",
    "extra_conditions": [
      ["51", "0xattacker_puzzle_hash_here", "1000000000000"]
    ]
  }
}
```

`parseDappParams` accepts `extra_conditions` because it is present in the inherited parent schema. The condition is forwarded to `create_offer_for_ids` on the daemon. The confirmation dialog displays `extra_conditions` as raw JSON. The user, seeing a normal-looking offer, confirms. The resulting spend bundle includes a `CREATE_COIN` condition sending 1 XCH to the attacker in addition to the stated offer terms.

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L10-17)
```typescript
export type ParamSchema = {
  name: string;
  label: () => string;
  isOptional?: boolean;
  hide?: boolean; // hidden from the confirm dialog - still showed under json details
  type: 'string' | 'number' | 'bool' | 'bigint' | 'json';
  humanize?: 'mojo-to-xch' | 'mojo-to-cat';
};
```

**File:** packages/gui/src/electron/commands/Commands.ts (L313-339)
```typescript
      // TODO verify rest if needed for DAPP, if not use for dapp separate params
      {
        name: 'offer_only',
        label: () => i18n._(/* i18n */ { id: 'Omit transactions data' }),
        type: 'bool',
        isOptional: true,
        dappAllowed: true,
      },
      {
        name: 'extra_conditions',
        label: () => i18n._(/* i18n */ { id: 'Extra Conditions' }),
        type: 'json',
        isOptional: true,
      },
      {
        name: 'coin_ids',
        label: () => i18n._(/* i18n */ { id: 'Coin Ids' }),
        type: 'json',
        isOptional: true,
      },
      {
        name: 'allow_unsynced',
        label: () => i18n._(/* i18n */ { id: 'Allow Unsynced' }),
        type: 'bool',
        isOptional: true,
      },
    ],
```

**File:** packages/gui/src/electron/commands/Commands.ts (L340-347)
```typescript
    dapp: [
      {
        command: 'chia_createOfferForIds',
        preserveNestedDataKeys: true,
        title: () => i18n._(/* i18n */ { id: 'Create Offer for Ids' }),
      },
    ],
  },
```

**File:** packages/gui/src/electron/commands/Commands.ts (L349-370)
```typescript
  'chia_wallet.take_offer': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Take Offer' }),
    message: () => i18n._(/* i18n */ { id: 'Please carefully review and confirm this offer acceptance.' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Accept' }),
    params: [
      { name: 'fee', label: () => i18n._(/* i18n */ { id: 'Fee' }), type: 'bigint', humanize: 'mojo-to-xch' },
      { name: 'offer', label: () => i18n._(/* i18n */ { id: 'Offer' }), type: 'string' },
      // TODO verify rest if needed for DAPP, if not use for dapp separate params
      {
        name: 'extra_conditions',
        label: () => i18n._(/* i18n */ { id: 'Extra Conditions' }),
        type: 'json',
        isOptional: true,
      },
    ],
    dapp: [
      {
        command: 'chia_takeOffer',
        title: () => i18n._(/* i18n */ { id: 'Take Offer' }),
      },
    ],
  },
```

**File:** packages/gui/src/electron/commands/parseDappParams.ts (L17-38)
```typescript
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

**File:** packages/api/src/services/WalletService.ts (L348-357)
```typescript
  async createOfferForIds<TArgs extends CreateOfferForIdsArgs>(args: TArgs): Promise<CreateOfferForIdsResult<TArgs>> {
    const { disableJSONFormatting, driverDict, extraConditions, coinIds, ...restArgs } = args;
    return this.command<CreateOfferForIdsResult<TArgs>>(
      'create_offer_for_ids',
      { driver_dict: driverDict, extra_conditions: extraConditions, coin_ids: coinIds, ...restArgs },
      false,
      undefined,
      disableJSONFormatting,
    );
  }
```

**File:** packages/gui/src/components/walletConnect/WalletConnectProvider.tsx (L310-366)
```typescript
      const {
        id,
        topic,
        params: {
          request: { method, params },
          chainId,
        },
      } = event;

      const pairTopic = getPairingTopicForSession(currentClient, topic);
      if (!pairTopic) {
        try {
          await respondSessionRequestError(currentClient, topic, id, 'Pairing not found', WcErrorCode.USER_REJECTED);
        } catch (e) {
          log('Failed to respond to session request without pairing:', e);
        }

        try {
          await currentClient.disconnect({ topic, reason: getSdkError('USER_DISCONNECTED') });
        } catch (e) {
          log('Failed to disconnect session without pairing:', e);
        }
        return;
      }

      const pair = await window.permissionsAPI.findPair(pairTopic);
      if (!pair) {
        try {
          await respondSessionRequestError(currentClient, topic, id, 'Pair not found', WcErrorCode.USER_REJECTED);
        } catch (e) {
          log('Failed to respond to orphan session request:', e);
        }

        try {
          await currentClient.disconnect({ topic, reason: getSdkError('USER_DISCONNECTED') });
        } catch (e) {
          log('Failed to disconnect orphan session:', e);
        }
        return;
      }

      const isMainnet = isWalletConnectChainIdMainnet(chainId);

      // parse fingerprint
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
