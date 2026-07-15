### Title
Stale WalletConnect Pair Records Persist After Key Deletion, Bypassing Re-Approval on Key Re-Import - (File: `packages/core/src/screens/SelectKey/WalletDeleteDialog.tsx`, `packages/gui/src/electron/utils/pairStore.ts`)

### Summary
When a user deletes a wallet key via `WalletDeleteDialog`, the WalletConnect pair records (including granted commands and bypass permissions) stored in `dapp-pairs.yaml` are never revoked. If the user re-imports the same mnemonic (same fingerprint), the previously-paired dApp regains full access — including any "always allow" bypass permissions — without any re-approval prompt, silently bypassing the WalletConnect approval gate.

### Finding Description

`WalletDeleteDialog.handleSubmit` calls `deleteKey({ fingerprint })` and `removeFingerprintPrefs()`, but performs no WalletConnect pair cleanup:

```typescript
async function handleSubmit(values: FormData) {
  await deleteKey({ fingerprint }).unwrap();
  removeFingerprintPrefs();   // only cleans up UI prefs
  onClose?.();
  // ← no call to permissionsAPI.revokePair for pairs bound to this fingerprint
}
``` [1](#0-0) 

WalletConnect pairs are persisted to disk in `dapp-pairs.yaml` via `pairStore.ts`:

```typescript
const FILE = 'dapp-pairs.yaml';
// ...
function persist(pairs: PairRecord[]) {
  writeData({ pairs }, getPath());
  cache = pairs;
}
``` [2](#0-1) 

Each `PairRecord` stores the `fingerprint`, granted `commands`, and `bypass` list: [3](#0-2) 

The main process IPC handlers for `deleteKey` (forwarded to the Chia daemon via `WalletService.deleteKey`) have no corresponding `removePair` call for pairs bound to the deleted fingerprint. The only way pairs are removed is via the explicit `REVOKE_PAIR` handler:

```typescript
ipcMainHandle(PermissionsAPI.REVOKE_PAIR, (topic: string) => {
  removePair(topic);
});
``` [4](#0-3) 

This is never triggered during key deletion.

### Impact Explanation

`dispatchPairRequest` enforces that `loggedInFingerprint === pair.fingerprint` at command execution time, so the stale pair cannot be exploited while a *different* key is active. However, the attack window opens the moment the user re-imports the same mnemonic (same fingerprint):

1. User pairs dApp with fingerprint `F`, grants bypass for commands like `chia_getWalletBalance`, `chia_getWallets`, `chia_showNotification`.
2. User deletes the key, believing all dApp access is revoked.
3. User re-imports the same mnemonic (fingerprint `F` again) to continue using their wallet.
4. The stale pair record with `fingerprint: F` and its full `bypass` list is still in `dapp-pairs.yaml`.
5. `dispatchPairRequest` now passes all checks — `loggedInFingerprint === pair.fingerprint` — and bypassed commands execute without any confirmation prompt. [5](#0-4) 

Additionally, non-bypassed commands (e.g., `chia_sendTransaction`) are still requestable by the dApp with a confirmation dialog — the user sees a prompt from a dApp they believed they had fully revoked. The pair also continues to appear as "Connected" in the WalletConnect UI, misleading the user about their security posture. [6](#0-5) 

### Likelihood Explanation

This occurs every time a user deletes a key while any WalletConnect pair is bound to that fingerprint and subsequently re-imports the same mnemonic — a common recovery/reset workflow. No special attacker capability is required beyond having previously been paired.

### Recommendation

In `WalletDeleteDialog.handleSubmit` (or in the main-process `deleteKey` handler), enumerate all pairs whose `fingerprint` matches the deleted key and call `revokePair` (or `removePair` in the main process) for each:

```typescript
async function handleSubmit(values: FormData) {
  await deleteKey({ fingerprint }).unwrap();
  removeFingerprintPrefs();
  // Revoke all WalletConnect pairs bound to this fingerprint
  const pairs = await window.permissionsAPI.getPairs();
  await Promise.all(
    pairs
      .filter((p) => p.fingerprint === fingerprint)
      .map((p) => disconnectPair(p.topic))
  );
  onClose?.();
}
```

The same cleanup should be applied for `deleteAllKeys`.

### Proof of Concept

1. Launch the Chia GUI with WalletConnect enabled.
2. Pair a dApp with wallet fingerprint `F`; grant "always allow" for `chia_getWalletBalance`.
3. Confirm the pair appears in Settings → Integrations.
4. Delete the key with fingerprint `F` via the key selection screen.
5. Re-import the same mnemonic (fingerprint `F` is restored).
6. From the dApp, send a `chia_getWalletBalance` request — it executes immediately with no confirmation dialog, using the stale bypass permission from the deleted key's pair record.
7. Observe that `dapp-pairs.yaml` still contains the pair entry with `fingerprint: F` and the bypass list intact. [7](#0-6) [8](#0-7)

### Citations

**File:** packages/core/src/screens/SelectKey/WalletDeleteDialog.tsx (L89-103)
```typescript
  function removeFingerprintPrefs() {
    delete fingerprintPrefs[fingerprint];
    setFingerprintPrefs(fingerprintPrefs);
    const newSortedWalletsPrefs = sortedWalletsPrefs.filter((f: string) => f !== String(fingerprint));
    setSortedWalletsPrefs(newSortedWalletsPrefs);
  }

  async function handleSubmit(values: FormData) {
    if (values.fingerprint !== fingerprint.toString()) {
      throw new Error(t`Fingerprint does not match`);
    }
    await deleteKey({ fingerprint }).unwrap();
    removeFingerprintPrefs();
    onClose?.();
  }
```

**File:** packages/gui/src/electron/utils/pairStore.ts (L7-48)
```typescript
const FILE = 'dapp-pairs.yaml';

let cache: PairRecord[] | undefined;

function getPath() {
  const userDataDir = getUserDataDir();
  if (!userDataDir) {
    throw new Error('userDataDir needs to be initialized');
  }

  return path.join(userDataDir, FILE);
}

function load(): PairRecord[] {
  if (cache) {
    return cache;
  }

  const data = readData(getPath());

  const pairRecords: PairRecord[] = [];

  if (data?.pairs && Array.isArray(data.pairs)) {
    for (const pair of data.pairs) {
      try {
        const record = pairRecordSchema.parse(pair);
        pairRecords.push(record);
      } catch (error) {
        console.error(`Invalid pair record: ${pair}`, error);
      }
    }
  }

  cache = pairRecords;
  return pairRecords;
}

function persist(pairs: PairRecord[]) {
  writeData({ pairs }, getPath());

  cache = pairs;
}
```

**File:** packages/gui/src/electron/utils/pairStore.ts (L50-56)
```typescript
export function getPairs(): PairRecord[] {
  return [...load()];
}

export function findPair(topic: string): PairRecord | undefined {
  return load().find((p) => p.topic === topic);
}
```

**File:** packages/gui/src/@types/PermissionsService.ts (L11-20)
```typescript
export type PermissionsPairRecord = {
  topic: string;
  mainnet: boolean;
  metadata: PermissionsPairMetadata;
  fingerprint: number;
  /** Wire form `chia_<name>`. Granted at pairing; empty = deny-all. */
  commands: string[];
  /** Whether this pair has any command-level "always allow" overrides. */
  hasBypass: boolean;
};
```

**File:** packages/gui/src/electron/main.tsx (L248-250)
```typescript
ipcMainHandle(PermissionsAPI.REVOKE_PAIR, (topic: string) => {
  removePair(topic);
});
```

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L40-58)
```typescript
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

  // if command is bypassed return true
  if (pair.bypass.includes(command)) {
    return process(context);
```

**File:** packages/gui/src/components/walletConnect/WalletConnectConnections.tsx (L61-98)
```typescript
  return (
    <Flex flexDirection="column" gap={1}>
      <Flex flexDirection="column" gap={1} paddingX={2} paddingY={1.5}>
        <Typography variant="h6">
          <Trans>Connected Applications</Trans>
        </Typography>
        {isLoading ? (
          <Loading center />
        ) : enabled && pairs.length > 0 ? (
          <Flex flexDirection="column">
            {pairs.map((pair) => (
              <Flex alignItems="center" key={pair.topic} justifyContent="space-between">
                <Flex alignItems="center" gap={1}>
                  <CheckCircleTwoToneIcon color={pair.sessions > 0 ? 'primary' : 'secondary'} />
                  <Typography>{pair.metadata?.name ?? <Trans>Unknown Application</Trans>}</Typography>
                </Flex>
                <More>
                  <MenuItem onClick={() => handleEdit(pair.topic)} close>
                    <ListItemIcon>
                      <EditIcon fontSize="small" color="info" />
                    </ListItemIcon>
                    <Typography variant="inherit" noWrap>
                      <Trans>Edit</Trans>
                    </Typography>
                  </MenuItem>
                  <MenuItem onClick={() => handleDisconnectPair(pair.topic)} close>
                    <ListItemIcon>
                      <DeleteIcon fontSize="small" color="info" />
                    </ListItemIcon>
                    <Typography variant="inherit" noWrap>
                      <Trans>Disconnect</Trans>
                    </Typography>
                  </MenuItem>
                </More>
              </Flex>
            ))}
          </Flex>
        ) : null}
```
