### Title
Attacker-Controlled Block Height in `getRandomSource(uint64)` Precompile Enables Randomness Cherry-Picking - (File: `fvm/evm/precompiles/arch.go`)

### Summary

The Cadence Arch precompile exposes `getRandomSource(uint64 blockHeight)` to all EVM callers. Because the `blockHeight` argument is fully attacker-controlled and the `RandomBeaconHistory` contract stores every past block's random source on-chain, any EVM caller can enumerate the entire history of random sources and supply whichever block height produces a favorable outcome. This is the direct structural analog of the original `PrizePool` finding: an attacker-controlled index into a public array of random values.

### Finding Description

`randomnessSource.Run()` in `fvm/evm/precompiles/arch.go` decodes the caller-supplied `uint64` height from the EVM call input and forwards it without restriction to `randomSourceProvider`:

```go
// fvm/evm/precompiles/arch.go  lines 171-188
func (r *randomnessSource) Run(input []byte) ([]byte, error) {
    height, err := ReadUint64(input, 0)   // ← fully attacker-controlled
    if err != nil {
        return nil, err
    }
    rand, err := r.randomSourceProvider(height)  // ← no restriction on height
    ...
}
```

`randomSourceProvider` in `fvm/evm/handler/precompiles.go` passes that height directly to `RandomBeaconHistory.sourceOfRandomness`:

```go
// fvm/evm/handler/precompiles.go  lines 62-98
func randomSourceProvider(contractAddress flow.Address, backend backends.Backend) func(uint64) ([]byte, error) {
    return func(blockHeight uint64) ([]byte, error) {
        value, err := backend.Invoke(
            ...
            FunctionName: "sourceOfRandomness",
            ...
            []cadence.Value{cadence.NewUInt64(blockHeight)},  // ← attacker value
        )
        ...
    }
}
```

`RandomBeaconHistory` accumulates one random source per block via the system-chunk heartbeat. Because every past entry is publicly readable and the precompile imposes no constraint on which height may be queried, the full history is an open menu from which any EVM caller can pick the entry that yields the most favorable outcome.

The only guard that exists is that the requested height must be strictly less than the current block height (enforced inside `RandomBeaconHistory.sourceOfRandomness`). That guard prevents querying a *future* block, but it does nothing to prevent cherry-picking among the thousands of already-finalized blocks.

**Attacker-controlled entry path:**

1. Attacker deploys (or interacts with) an EVM lottery/raffle/game contract that calls `getRandomSource(uint64 height)` and uses the returned bytes to determine a winner.
2. Attacker reads `RandomBeaconHistory` off-chain (public state) to obtain every stored random source.
3. Attacker simulates the lottery outcome for each historical height until finding one that makes them the winner.
4. Attacker submits the EVM transaction supplying that specific `height` — the contract receives the pre-selected random source and declares the attacker the winner.

No privileged keys, staked nodes, or quorum compromise are required. The only precondition is the ability to send an EVM transaction, which is available to any unprivileged user.

### Impact Explanation

Any EVM smart contract on Flow EVM that uses `getRandomSource(uint64)` to resolve randomness-dependent outcomes (lotteries, NFT raffles, on-chain games, yield distributions) is immediately exploitable. An attacker with no special privileges can deterministically win every such draw by selecting the block height whose random source produces the desired result. The impact is direct, unauthorized theft of on-chain assets from other participants.

### Likelihood Explanation

High. The `getRandomSource(uint64)` precompile is the documented mechanism for EVM contracts to obtain Flow's verifiable randomness. Developers building lottery or raffle contracts are the primary target audience. The attack requires only: (a) reading public chain state to enumerate historical random sources, (b) off-chain simulation to find a favorable height, and (c) submitting a single EVM transaction. No brute-force, no privileged access, no timing dependency.

### Recommendation

1. **Remove the caller-controlled height parameter from `getRandomSource`.** The precompile should return the random source for the *current* block only (analogous to `revertibleRandom()`), eliminating the ability to cherry-pick from history.
2. **If historical lookup is required for commit-reveal schemes**, enforce that the contract itself (not the caller) commits to a specific future block height on-chain before that block is produced, and only allows redemption against that committed height. The precompile cannot enforce this; it must be enforced at the application layer with explicit protocol guidance.
3. **Add a code comment and developer-facing warning** to `randomnessSource.Run()` and `randomSourceProvider` stating that passing a caller-controlled height is insecure and that `revertibleRandom()` should be used for single-transaction randomness needs.

### Proof of Concept

```solidity
// Attacker's EVM contract
interface CadenceArch {
    function getRandomSource(uint64 height) external view returns (bytes32);
}

contract LotteryExploit {
    CadenceArch constant arch = CadenceArch(0x0000000000000000000000010000000000000001);

    // Attacker calls this after off-chain simulation identifies `winningHeight`
    function claimWithChosenHeight(uint64 winningHeight) external view returns (bytes32) {
        // Returns the pre-selected historical random source
        return arch.getRandomSource(winningHeight);
        // Downstream lottery contract uses this value to pick a winner —
        // attacker already knows it resolves in their favor.
    }
}
```

**Step-by-step:**
1. Read all entries from `RandomBeaconHistory` (public Cadence state).
2. For each stored `(blockHeight, randomSource)` pair, simulate `randomSource % totalTickets` to find the index that maps to the attacker's ticket.
3. Call `claimWithChosenHeight(winningHeight)` — the lottery contract receives the attacker-chosen random source and awards the prize.

**Root cause lines:** [1](#0-0) [2](#0-1)

### Citations

**File:** fvm/evm/precompiles/arch.go (L171-177)
```go
func (r *randomnessSource) Run(input []byte) ([]byte, error) {
	height, err := ReadUint64(input, 0)
	if err != nil {
		return nil, err
	}
	rand, err := r.randomSourceProvider(height)
	if err != nil {
```

**File:** fvm/evm/handler/precompiles.go (L62-78)
```go
func randomSourceProvider(contractAddress flow.Address, backend backends.Backend) func(uint64) ([]byte, error) {
	return func(blockHeight uint64) ([]byte, error) {
		value, err := backend.Invoke(
			environment.ContractFunctionSpec{
				AddressFromChain: func(_ flow.Chain) flow.Address {
					return contractAddress
				},
				LocationName: "RandomBeaconHistory",
				FunctionName: "sourceOfRandomness",
				ArgumentTypes: []sema.Type{
					sema.UInt64Type,
				},
			},
			[]cadence.Value{
				cadence.NewUInt64(blockHeight),
			},
		)
```
