### Title
Test Addresses Hardcoded into Production Unblockable List Permanently Bypass Admin Blocklist - (File: app/unblockable.go)

### Summary
Two addresses annotated `// test` are compiled into the production `unblockableHexAddresses` constant in `app/unblockable.go`. Because `IsUnblockable` is consulted at every blocklist-load site, any entity controlling either address can never be blocked by the Cronos admin, regardless of what is submitted via `MsgStoreBlockList`.

### Finding Description
`app/unblockable.go` defines a hardcoded list of EVM addresses that are silently filtered out of every blocklist update, both at node startup (`setAnteHandler`) and at every proposal-time blocklist refresh (`SetBlockList`). The list ends with two entries preceded by the comment `// test`:

```
// test
"0xCC5d9bF5C3662D8A86A45ed23B300bc06ab36644",
"0xDaB2C01b1eBdf1D33eCF6Aff3a29b977a1EFba41",
``` [1](#0-0) 

These addresses are compiled into `unblockableSet` at package-init time and are therefore active on every production node. [2](#0-1) 

`IsUnblockable` is called in two enforcement sites:

1. **`app/proposal.go` `SetBlockList`** — when the validator-side proposal handler decrypts and loads a new blocklist, any address for which `IsUnblockable` returns `true` is silently `continue`d and never inserted into the active blocklist map. [3](#0-2) 

2. **`app/app.go` `setAnteHandler`** — when the node starts or reloads its ante-handler blacklist, the same filter is applied, so the addresses are never placed into `blockedMap`. [4](#0-3) 

The result is that `MsgStoreBlockList` submissions that include either test address are accepted on-chain (the message itself succeeds), but the addresses are stripped before the enforcement maps are built, so the block never takes effect.

### Impact Explanation
Any entity that controls `0xCC5d9bF5C3662D8A86A45ed23B300bc06ab36644` or `0xDaB2C01b1eBdf1D33eCF6Aff3a29b977a1EFba41` has a permanent, unconditional bypass of the Cronos admin blocklist. The admin has no on-chain or off-chain mechanism to override this; the bypass is baked into the binary. This satisfies the **High** impact criterion: *Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks*.

### Likelihood Explanation
The attacker path requires only that an adversary control one of the two addresses — no privilege escalation, no key leakage, no governance compromise. The addresses are externally observable in the open-source binary. The bypass is permanent for the lifetime of any node running this binary version.

### Recommendation
Remove the two `// test` entries from `unblockableHexAddresses` in `app/unblockable.go`. Test-only addresses must never appear in a production constant that governs security enforcement. If these addresses are needed for integration tests, they should be injected only in test fixtures, not compiled into the production binary. [5](#0-4) 

### Proof of Concept
1. Attacker holds the private key for `0xCC5d9bF5C3662D8A86A45ed23B300bc06ab36644`.
2. Admin submits `MsgStoreBlockList` containing the attacker's bech32-encoded address.
3. On every validator, `SetBlockList` iterates the decrypted list; at the attacker's entry, `IsUnblockable` returns `true` and the entry is skipped (`continue`).
4. The attacker's address is absent from `h.blocklist`; `ValidateTransaction` never rejects the attacker's transactions.
5. Simultaneously, `setAnteHandler` also skips the address, so `BlockAddressesDecorator` never blocks it at CheckTx either.
6. The attacker transacts freely and cannot be stopped by any admin action short of a binary upgrade.

### Citations

**File:** app/unblockable.go (L14-44)
```go
var unblockableHexAddresses = []string{
	"0x007F588ca3FFe53F20cb03553Ca38bb13542FF89",
	"0x4356e8c6Ddca1964b22ECd35cb74A74BDdeDe2a3",
	"0x3D7F2C478aAfdB65542BCB44bCeeC05849999d2D",
	"0xC543052518F7787936522926242f86BADD39Cb46",
	"0x405fCcd57dA8ffbd0F2C38D57B1DA933b00B7bC6",
	"0x31f58b04f03d791c56de058211f0c767af96b464",
	"0xA6dE01a2d62C6B5f3525d768f34d276652C554c8",
	"0x192E362B2810f604e0618B5033d26F3b85E05AF9",
	"0xA4EC772557A0E72985EA2532B72f363fA5379C11",
	"0xeae603121f38d43e801254d172fd0bee959918b6",
	"0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d",
	"0x81D40F21F12A8F0E3252Bccb954D722d4c464B64",
	"0xfd78EE919681417d192449715b2594ab58f5D002",
	"0x1CcaFdffBC1b7B5C499c97322F961B7d929a41b4",
	"0x01fB02b8209c8A5c271a4fCB700Bfb9C80b5B614",
	"0xec546b6B005471ECf012e5aF77FBeC07e0FD8f78",
	"0xda95b41655EA94d93241d97432DAfb6B27148289",
	"0x3812789185aF19B2002c0DfAcC3C7926eCbA674D",
	"0xc375fe4b88c5858bD5521917D0C3418856Ac1FB1",
	"0x69F762B2f1706e15eF77F7F8C5b07Fda66844d67",
	"0x7ea46aDC49Eb1228350f76327c94b9F06A032bd9",
	"0x4E6B78bF26881E38FfB939945116Dd8d4DD48551",
	"0xBE3866F2Cdddc6A5dE252e50EFD9429BD3495007",
	"0x26132C4bCceFa08bBEa4Ca85E3dBB797Ba8C1f09",
	"0x1a061EDeA58DA99c2d09FdD1f9e6BA9DaB1413ff",
	"0xa64915eaf58b245b2d2bbe7a7dc8c69956ac8670",
	// test
	"0xCC5d9bF5C3662D8A86A45ed23B300bc06ab36644",
	"0xDaB2C01b1eBdf1D33eCF6Aff3a29b977a1EFba41",
}
```

**File:** app/unblockable.go (L46-48)
```go
// unblockableSet maps the raw 20-byte account-address form of each unblockable
// address to an empty struct, for O(1) lookup.
var unblockableSet = buildUnblockableSet(unblockableHexAddresses)
```

**File:** app/proposal.go (L243-256)
```go
	for _, s := range blocklist.Addresses {
		addr, err := h.addressCodec.StringToBytes(s)
		if err != nil {
			return fmt.Errorf("invalid bech32 address: %s, err: %w", s, err)
		}
		if IsUnblockable(addr) {
			continue
		}
		encoded, err := h.addressCodec.BytesToString(addr)
		if err != nil {
			return fmt.Errorf("invalid bech32 address: %s, err: %w", s, err)
		}
		m[encoded] = struct{}{}
	}
```

**File:** app/app.go (L1242-1253)
```go
	blockedMap := make(map[string]struct{}, len(blacklist))
	for _, str := range blacklist {
		addr, err := sdk.AccAddressFromBech32(str)
		if err != nil {
			return fmt.Errorf("invalid bech32 address: %s, err: %w", str, err)
		}
		if IsUnblockable(addr) {
			continue
		}

		blockedMap[addr.String()] = struct{}{}
	}
```
