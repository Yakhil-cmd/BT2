### Title
`NoHeight = 0` Sentinel Collision Silently Bypasses Version-Compatibility End-Boundary Check in `CompatibleAtBlock` - (File: `engine/common/version/version_control.go`)

---

### Summary

`VersionControl.CompatibleAtBlock` uses `NoHeight = uint64(0)` as a sentinel meaning "no boundary set". Because `0` is also a valid block height, when `endHeight` is legitimately stored as `0` (which occurs whenever a version beacon carries `boundary.BlockHeight = 1`), the guard `endHeight != NoHeight` evaluates to `false` and the entire end-boundary enforcement is silently skipped. The function then returns `true` (compatible) for every queried height, including heights that should be rejected. Every script-execution and account-query API on the Access Node passes through this check, so any unprivileged API caller can obtain execution results from an incompatible node version.

---

### Finding Description

`NoHeight` is declared as a package-level variable with value `0`:

```go
// engine/common/version/version_control.go:33
var NoHeight = uint64(0)
```

It is used as the initial / "not-set" value for both `startHeight` and `endHeight`:

```go
// engine/common/version/version_control.go:142-143
startHeight: atomic.NewUint64(NoHeight),
endHeight:   atomic.NewUint64(NoHeight),
```

Both `initBoundaries` and `blockFinalized` write the end boundary as `boundary.BlockHeight - 1`:

```go
// engine/common/version/version_control.go:238
v.endHeight.Store(boundary.BlockHeight - 1)

// engine/common/version/version_control.go:381
newEndHeight = boundary.BlockHeight - 1
```

When a version beacon carries `boundary.BlockHeight = 1` (the first block requiring a new node version), `endHeight` is stored as `0`, which is numerically identical to `NoHeight`.

`CompatibleAtBlock` then guards the end-boundary check with:

```go
// engine/common/version/version_control.go:287-290
endHeight := v.endHeight.Load()
if endHeight != NoHeight && height > endHeight {
    return false, nil
}
```

Because `endHeight == NoHeight == 0`, the condition `endHeight != NoHeight` is `false`. The check is never entered. The function falls through and returns `true` (compatible) for **every** height, including heights `> 0` that should be rejected.

`VersionBeacon.Validate()` does not prevent a boundary at height 1:

```go
// model/flow/version_beacon.go:123
if i != 0 && previousHeight >= boundary.BlockHeight {
```

The `i != 0` guard means the first boundary can carry any `BlockHeight`, including `1`.

---

### Impact Explanation

`CompatibleAtBlock` is the authoritative version-compatibility gate called by `ScriptExecutor.checkHeight`:

```go
// engine/access/rpc/backend/script_executor.go:256-264
if s.versionControl != nil {
    compatible, err := s.versionControl.CompatibleAtBlock(height)
    ...
    if !compatible {
        return ErrIncompatibleNodeVersion
    }
}
```

`checkHeight` is invoked before every local script execution and account query:
- `ExecuteAtBlockHeight`
- `GetAccountAtBlockHeight`
- `GetAccountBalance`
- `GetAccountAvailableBalance`
- `GetAccountKeys` / `GetAccountKey`
- `GetAccountCode`
- `RegisterValue`
- `GetStorageSnapshot`

When the end-boundary check is bypassed, the Access Node executes Cadence scripts against register state at block heights for which its FVM/Cadence version is not compatible. This produces silently incorrect execution results — wrong account balances, wrong NFT ownership proofs, wrong contract reads — returned to any API caller without error. Off-chain systems (wallets, DeFi frontends, bridges) that rely on these results for authorization or asset-accounting decisions receive corrupted data.

---

### Likelihood Explanation

A version beacon with `boundary.BlockHeight = 1` is required to trigger the collision. The `NodeVersionBeacon` smart contract is callable by the service account; the on-chain `Validate()` logic does not enforce a minimum boundary height. The condition is therefore reachable through a legitimate (or misconfigured) on-chain governance action. Once the beacon is sealed, every Access Node running the affected code silently disables its end-boundary check for the remainder of the spork, and every unprivileged gRPC/REST caller can trigger incorrect script execution with no special privileges.

---

### Recommendation

Replace the zero-valued sentinel with a value that cannot collide with any real block height. The idiomatic Go approach is to use `math.MaxUint64` as the "not set" sentinel, or to use a separate boolean flag:

```go
// Option A – use math.MaxUint64 as sentinel
var NoHeight = uint64(math.MaxUint64)

// Option B – track "set" state separately
type heightBound struct {
    value *atomic.Uint64
    set   *atomic.Bool
}
```

The guard in `CompatibleAtBlock` and all callers of `NoHeight` must be updated consistently. Additionally, `VersionBeacon.Validate()` should enforce `boundary.BlockHeight >= 1` for the first entry to prevent a boundary that would produce `endHeight = 0` under the current arithmetic.

---

### Proof of Concept

1. The `NodeVersionBeacon` service-account contract emits a `VersionBeacon` with a single boundary: `{BlockHeight: 1, Version: "99.0.0"}`.
2. The beacon is sealed. `blockFinalized` processes it and stores `endHeight = boundary.BlockHeight - 1 = 0`.
3. An Access Node running version `0.x.y` (lower than `99.0.0`) calls `CompatibleAtBlock(500)`:
   - `endHeight.Load()` returns `0`.
   - `endHeight != NoHeight` → `0 != 0` → `false`.
   - The end-boundary branch is skipped.
   - The function returns `(true, nil)`.
4. `ScriptExecutor.checkHeight(500)` passes without error.
5. Any unprivileged REST/gRPC caller invoking `ExecuteScriptAtBlockHeight(script, height=500)` receives a result computed by an incompatible FVM version, with no indication of the incompatibility.

**Key lines:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** engine/common/version/version_control.go (L33-33)
```go
var NoHeight = uint64(0)
```

**File:** engine/common/version/version_control.go (L237-239)
```go
			} else {
				v.endHeight.Store(boundary.BlockHeight - 1)
				v.log.Info().
```

**File:** engine/common/version/version_control.go (L287-291)
```go
	endHeight := v.endHeight.Load()
	// Check if the end height is set and the height is greater than the end height. If so, return false indicating that the height is not compatible.
	if endHeight != NoHeight && height > endHeight {
		return false, nil
	}
```

**File:** engine/common/version/version_control.go (L380-382)
```go
			if ver.Compare(*v.nodeVersion) > 0 {
				newEndHeight = boundary.BlockHeight - 1

```

**File:** model/flow/version_beacon.go (L123-132)
```go
		if i != 0 && previousHeight >= boundary.BlockHeight {
			return eventError(
				"higher requirement (index=%d) height %d "+
					"at or below previous height (index=%d) %d",
				i,
				boundary.BlockHeight,
				i-1,
				previousHeight,
			)
		}
```

**File:** engine/access/rpc/backend/script_executor.go (L251-265)
```go
	if height > s.maxCompatibleHeight.Load() || height < s.minCompatibleHeight.Load() {
		return ErrIncompatibleNodeVersion
	}

	// Version control feature could be disabled. In such a case, ignore related functionality.
	if s.versionControl != nil {
		compatible, err := s.versionControl.CompatibleAtBlock(height)
		if err != nil {
			return fmt.Errorf("failed to check compatibility with block height %d: %w", height, err)
		}

		if !compatible {
			return ErrIncompatibleNodeVersion
		}
	}
```
