### Title
WalletConnect dApp Can Inject Unintelligible Clawback Timelock via `puzzle_decorator` in `chia_sendTransaction` Confirmation Dialog — (`packages/gui/src/electron/commands/Commands.ts`)

---

### Summary

A malicious WalletConnect dApp can include `puzzle_decorator: [{decorator:"CLAWBACK", clawbackTimelock:31536000}]` in a `chia_sendTransaction` request. The confirmation dialog renders this field as raw JSON under the opaque label "Puzzle Decorator" with no humanization, no explanation of what CLAWBACK means, and no conversion of the timelock seconds to a human-readable duration. A user who clicks "Send" unknowingly sends a clawback-encumbered payment: the recipient cannot claim the funds for 1 year.

---

### Finding Description

**Step 1 — `puzzle_decorator` is an explicitly allowed, non-hidden param in the schema.** [1](#0-0) 

The field is `isOptional: true` but has no `hide: true` flag and no `humanize` property. It is typed as `'json'`.

**Step 2 — `parseDappParams` accepts it without restriction.** [2](#0-1) 

The allowlist check passes because `puzzle_decorator` is in the schema. For `type: 'json'`, no further coercion or validation is applied — the raw object passes through. [3](#0-2) 

**Step 3 — `humanizeParams` includes the field because it is present and not hidden.** [4](#0-3) 

Since `puzzle_decorator` is defined in the dApp's payload and `hide` is not set, it passes the filter and is rendered.

**Step 4 — `humanizeParamValue` renders it as raw pretty-printed JSON.** [5](#0-4) 

No `humanize` handler exists for `puzzle_decorator`. The user sees:

```
Puzzle Decorator
[
  {
    "decorator": "CLAWBACK",
    "clawbackTimelock": 31536000
  }
]
```

There is no explanation that:
- `CLAWBACK` means the recipient cannot claim the funds until the timelock expires
- `31536000` is 1 year in seconds
- The sender retains unilateral clawback authority over the payment

**Step 5 — After user approval, the transaction is dispatched with the clawback intact.** [6](#0-5) 

The `parsedParams` (including `puzzle_decorator`) are forwarded verbatim to `sendCommand` after the user clicks "Send".

---

### Impact Explanation

The recipient of what the user believed was an unconditional XCH payment cannot claim the funds for up to 1 year. The sender (whose wallet signed the transaction) retains clawback authority. A malicious dApp can systematically inject this into every `chia_sendTransaction` it initiates, causing all payments made through it to be clawback-encumbered without the user's informed consent. This is a direct, on-chain asset restriction with concrete financial impact.

This fits: **High — WalletConnect state causes a user to approve the wrong transaction modifier, resulting in custody/clawback restrictions applied without informed consent.**

---

### Likelihood Explanation

Any WalletConnect-connected dApp can trigger this. The user only needs to have paired with the dApp and approved the `chia_sendTransaction` command. No special permissions beyond the standard WalletConnect pairing are required. The attack is silent — the raw JSON is easy to overlook in a confirmation dialog that already shows amount, fee, and address.

---

### Recommendation

1. Add a dedicated `humanize` handler for `puzzle_decorator` in `humanizeParamValue.ts` that converts `CLAWBACK` + `clawbackTimelock` seconds into a human-readable warning, e.g.: *"Clawback enabled — recipient cannot claim funds for 1 year (365 days). You retain the right to claw back this payment."*
2. Alternatively, add a `humanize: 'puzzle-decorator'` key to the `puzzle_decorator` param schema entry in `Commands.ts` and implement the corresponding case in `humanizeParamValue`.
3. Consider whether `puzzle_decorator` should be allowed at all from WalletConnect dApps without an explicit, separate user acknowledgment step distinct from the standard send confirmation.

---

### Proof of Concept

1. Establish a WalletConnect session with the Chia GUI wallet.
2. From the dApp, call:
   ```json
   {
     "method": "chia_sendTransaction",
     "params": {
       "amount": "1000000000",
       "fee": "0",
       "address": "<recipient_address>",
       "puzzleDecorator": [{"decorator": "CLAWBACK", "clawbackTimelock": 31536000}]
     }
   }
   ```
3. Observe the confirmation dialog: it shows `Puzzle Decorator` with raw JSON `[{"decorator":"CLAWBACK","clawbackTimelock":31536000}]`. No human-readable explanation of the clawback or its duration is shown.
4. Click "Send". The transaction is submitted with the CLAWBACK puzzle decorator.
5. Verify on-chain that the recipient's coin is clawback-encumbered and cannot be claimed for 1 year.

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L162-167)
```typescript
      {
        name: 'puzzle_decorator',
        label: () => i18n._(/* i18n */ { id: 'Puzzle Decorator' }),
        type: 'json',
        isOptional: true,
      },
```

**File:** packages/gui/src/electron/commands/parseDappParams.ts (L34-38)
```typescript
  Object.keys(nextParams).forEach((key) => {
    if (!dappParamsMap.has(key)) {
      throw new Error(`param not allowed for dapp: ${key}`);
    }
  });
```

**File:** packages/gui/src/electron/commands/parseDappParams.ts (L62-98)
```typescript
    if (value !== undefined) {
      if (type === 'string') {
        nextParams[name] = String(value);
      } else if (type === 'number') {
        nextParams[name] = Number(value);
        if (Number.isNaN(nextParams[name])) {
          throw new Error(`Invalid number value for argument ${name}. Value: ${value}`);
        }
      } else if (type === 'bool') {
        if (typeof value !== 'boolean') {
          throw new Error(`Invalid boolean value for argument ${name}. Value: ${value}`);
        }
        nextParams[name] = value;
      } else if (type === 'bigint') {
        if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'bigint') {
          throw new Error(`Invalid bigint value for argument ${name}. Value: ${value}`);
        }

        if (typeof value === 'number' && !Number.isSafeInteger(value)) {
          throw new Error(`Invalid bigint value for argument ${name}. Value: ${value}`);
        }

        if (typeof value === 'string') {
          const trimmed = value.trim();
          if (trimmed === '') {
            throw new Error(`Invalid bigint value for argument ${name}. Value: ${value}`);
          }
        }

        const bigintValue = BigInt(value);
        if (bigintValue.toString() !== value.toString()) {
          throw new Error(`Invalid bigint value for argument ${name}. Value: ${value}`);
        }

        nextParams[name] = bigintValue;
      }
    }
```

**File:** packages/gui/src/electron/commands/humanizeParams.ts (L6-19)
```typescript
  const visibleParams = params.filter((param) => {
    const { hide, isOptional, name } = param;

    if (hide === true) {
      return false;
    }

    const isDefined = name in data;
    if (isOptional && !isDefined) {
      return false;
    }

    return true;
  });
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

**File:** packages/gui/src/electron/main.tsx (L285-310)
```typescript
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
```
