### Title
WalletConnect `chia_spendClawbackCoins` Confirmation Dialog Omits Amount, Direction, and Counterparty — Enables Blind Clawback Approval - (`packages/gui/src/electron/commands/Commands.ts`)

---

### Summary

The WalletConnect confirmation dialog for `chia_spendClawbackCoins` (`chia_wallet.spend_clawback_coins`) displays only raw hex coin IDs and a fee amount, with no human-readable XCH amount, no direction indicator (claim vs. clawback), and no counterparty address. A malicious dApp with the `chia_spendClawbackCoins` permission can trigger this dialog with attacker-chosen coin IDs, causing the user to approve a clawback spend without understanding its financial impact.

---

### Finding Description

The `chia_wallet.spend_clawback_coins` command definition in `Commands.ts` exposes only two params to the confirmation dialog: [1](#0-0) 

- `coin_ids` — type `json`, rendered by `humanizeParamValue` as `JSONBig.stringify(value, null, 2)`: a raw JSON array of hex strings.
- `fee` — type `bigint` with `humanize: 'mojo-to-xch'`: converted to XCH. [2](#0-1) 

The `Confirm.tsx` dialog renders these as labeled rows: [3](#0-2) 

The user therefore sees:
- **Coin Ids**: `["0xabc123..."]` (opaque hex)
- **Fee**: `0 XCH`

Nothing else. No XCH amount, no direction (claim vs. clawback), no counterparty address.

By contrast, the native `ClawbackClaimTransactionDialog` — used when the user initiates the action from the wallet UI — shows all three: [4](#0-3) 

The `isSpendCommand` guard confirms this command requires explicit user confirmation (no bypass): [5](#0-4) 

But the confirmation itself is uninformative.

---

### Impact Explanation

A malicious dApp with the `chia_spendClawbackCoins` permission can:

1. Query the wallet's transaction history (via other permitted WalletConnect read commands) to discover coin IDs of the user's pending clawback-protected outgoing payments.
2. Send `chia_spendClawbackCoins` with those coin IDs and `fee=0`.
3. The user sees a dialog titled "Confirm Clawback Spend" with only raw hex coin IDs and "0 XCH" fee — no indication of the amount being revoked, whether this is a claim or a clawback, or who the counterparty is.
4. If the user approves, the dApp causes the user to **claw back a legitimate outgoing payment**, revoking it from the intended recipient without the user understanding what they approved.

This is a direct financial impact: a payment the user intended to send is silently revoked. The recipient loses funds they were expecting.

---

### Likelihood Explanation

- Requires an active WalletConnect session and the `chia_spendClawbackCoins` permission — both are realistic for any dApp that legitimately handles clawback flows.
- The dApp can discover coin IDs via other permitted read commands (e.g., `chia_getTransactions`).
- The confirmation dialog provides no meaningful information to help the user reject a malicious request.
- The attack is fully local-testable with a WalletConnect-capable dApp.

---

### Recommendation

The `chia_wallet.spend_clawback_coins` command definition should be enriched to resolve coin IDs to human-readable context before presenting the confirmation dialog. Specifically, the dialog should display:

- The XCH amount of each coin being spent (resolved from coin records).
- The direction: whether each coin is a clawback (sender revoking) or a claim (recipient collecting).
- The counterparty address for each coin.

This mirrors what `ClawbackClaimTransactionDialog` already does for the native UI path. [6](#0-5) 

---

### Proof of Concept

1. Establish a WalletConnect session with a test dApp and grant it the `chia_spendClawbackCoins` permission.
2. Have the wallet send a clawback-protected XCH payment (e.g., 5 XCH, 1-day timelock) to a recipient address.
3. From the dApp, query transaction history to obtain the coin ID of the pending clawback-protected outgoing coin.
4. Send a WalletConnect `chia_spendClawbackCoins` request with `coin_ids=[<that_coin_id>]` and `fee=0`.
5. Observe the confirmation dialog: it shows only `Coin Ids: ["0x..."]` and `Fee: 0 XCH` — no amount, no direction, no address.
6. Approve the dialog.
7. Verify on-chain that the 5 XCH payment to the recipient has been clawed back (revoked), without the user having been shown the amount or direction at approval time.

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L631-646)
```typescript
  'chia_wallet.spend_clawback_coins': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Clawback Spend' }),
    message: () => i18n._(/* i18n */ { id: 'Please carefully review and confirm this clawback spend.' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Send' }),
    params: [
      { name: 'coin_ids', label: () => i18n._(/* i18n */ { id: 'Coin Ids' }), type: 'json' },
      { name: 'fee', label: () => i18n._(/* i18n */ { id: 'Fee' }), type: 'bigint', humanize: 'mojo-to-xch' },
    ],
    dapp: [
      {
        command: 'chia_spendClawbackCoins',
        title: () => i18n._(/* i18n */ { id: 'Claw back or claim claw back transaction' }),
        requiresSync: true,
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

**File:** packages/wallets/src/components/ClawbackClaimTransactionDialog.tsx (L56-57)
```typescript
export default function ClawbackClaimTransactionDialog(props: Props) {
  const { onClose, open, coinId, amountInMojo, fromOrTo, address } = props;
```

**File:** packages/wallets/src/components/ClawbackClaimTransactionDialog.tsx (L137-197)
```typescript
      <DialogTitle id="confirmation-dialog-title" sx={{ minWidth: '550px' }}>
        {fromOrTo === 'from' ? <Trans>Claim Transaction</Trans> : <Trans>Claw Back Transaction</Trans>}
        <IconButton
          aria-label="close"
          onClick={onClose}
          sx={{
            position: 'absolute',
            right: 8,
            top: 8,
            color: (theme) => (theme.palette.mode === 'dark' ? Color.Neutral[400] : Color.Neutral[500]),
          }}
        >
          <CloseIcon />
        </IconButton>
      </DialogTitle>
      {isGetAutoClaimLoading && (
        <>
          <DialogContent dividers>
            <Typography variant="body1">Loading...</Typography>
          </DialogContent>{' '}
          <DialogActions>
            <Button autoFocus onClick={handleClose} color="secondary">
              <Trans>Close</Trans>
            </Button>
          </DialogActions>
        </>
      )}
      {!isGetAutoClaimLoading && (
        <Form methods={methods} onSubmit={handleSubmit}>
          <DialogContent dividers>
            <Flex gap={2} flexDirection="column" sx={{ textAlign: 'center', alignItems: 'center' }}>
              <Box sx={{ mb: 3 }}>
                <Typography variant="h5">
                  <FormatLargeNumber value={mojoToChia(amountInMojo)} />{' '}
                  <Box
                    component="span"
                    sx={{ color: (theme) => (theme.palette.mode === 'dark' ? Color.Neutral[400] : Color.Neutral[500]) }}
                  >
                    {currencyCode}
                  </Box>
                </Typography>
                <Typography variant="subtitle1" sx={{ mt: 1 }}>
                  <Box
                    component="span"
                    sx={{ color: (theme) => (theme.palette.mode === 'dark' ? Color.Neutral[400] : Color.Neutral[500]) }}
                  >
                    {fromOrTo === 'from' ? <Trans>From:</Trans> : <Trans>To:</Trans>}{' '}
                  </Box>
                  <Tooltip
                    title={
                      <Flex flexDirection="column" gap={1}>
                        <Flex flexDirection="row" alignItems="center" gap={1}>
                          <Box maxWidth={200}>{address}</Box>
                          <CopyToClipboard value={address} fontSize="small" />
                        </Flex>
                      </Flex>
                    }
                  >
                    <span>{truncateValue(address, {})}</span>
                  </Tooltip>
                </Typography>
```

**File:** packages/gui/src/electron/commands/isSpendCommand.ts (L3-13)
```typescript
const SPEND_COMMANDS = new Set<keyof typeof Commands>([
  'chia_wallet.send_transaction',
  'chia_wallet.cat_spend',
  'chia_wallet.nft_transfer_nft',
  'chia_wallet.cancel_offer',
  'chia_wallet.create_offer_for_ids',
  'chia_wallet.take_offer',
  'chia_wallet.spend_clawback_coins',
  'chia_wallet.did_transfer_did',
  'chia_wallet.push_transactions',
]);
```
