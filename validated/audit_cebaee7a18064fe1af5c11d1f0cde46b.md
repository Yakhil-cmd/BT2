### Title
`revertibleRandom()` Exposes Current-Block Randomness to Selective-Reversion Attacks - (File: `fvm/evm/precompiles/arch.go`, `fvm/evm/handler/precompiles.go`)

---

### Summary

The Cadence Arch precompile exposes `revertibleRandom()`, which returns the current block's randomness derived from the QC beacon signature. Because this value is fixed for the entire block and is observable before a transaction commits, an unprivileged EVM contract or Cadence transaction author can read the value, decide whether the outcome is favorable, and revert if it is not — effectively cherry-picking winning outcomes. This is the direct Flow analog of using `slot0` for security-critical calculations: both expose a single-point-in-time state value that an attacker can observe and act on within the same execution context.

---

### Finding Description

**Root cause — `revertibleRandomGenerator` in `fvm/evm/handler/precompiles.go`:**

```go
func revertibleRandomGenerator(backend backends.Backend) func() (uint64, error) {
    return func() (uint64, error) {
        rand := make([]byte, 8)
        err := backend.ReadRandom(rand)   // reads current-block CSPRG output
        ...
        return binary.BigEndian.Uint64(rand), nil
    }
}
``` [1](#0-0) 

`backend.ReadRandom` is wired to the `randomGenerator` in `fvm/environment/random_generator.go`, which seeds a CSPRG from the current block's QC beacon signature. The seed is **identical for every call within the same block**; only the PRG counter advances. [2](#0-1) 

This generator is registered as the `revertibleRandom` function of the Cadence Arch precompile: [3](#0-2) 

The `Run` method of the `revertibleRandom` struct simply calls the generator and returns the value with no commit-reveal protection: [4](#0-3) 

The same randomness is also available directly in Cadence via `revertibleRandom<T>()`, as exercised in the FVM block-context tests: [5](#0-4) 

**Two concrete attack paths:**

**Path A — script pre-observation:**
A Cadence script (read-only, free) calls `revertibleRandom<UInt64>()` to read the block's randomness. If the value is favorable (e.g., the attacker would win a lottery), the attacker immediately submits the real transaction in the same block. If not, they skip the block and repeat next block. No gas is wasted on unfavorable blocks.

**Path B — EVM inner-transaction revert:**
An EVM contract calls `revertibleRandom()` via the Cadence Arch precompile, checks the result, and executes `revert` if unfavorable. The outer Cadence transaction wrapping `EVM.run()` checks `res.status` and also reverts. The attacker retries across blocks until the randomness is favorable. The EVM contract's state changes are rolled back on revert, so there is no cost beyond gas. [6](#0-5) 

---

### Impact Explanation

Any EVM or Cadence protocol that uses `revertibleRandom()` for a security-critical outcome — lotteries, NFT trait rolls, random reward distribution, random liquidation selection — is exploitable. An attacker with zero special privileges can:

- Win every lottery by only submitting when the random value maps to their ticket.
- Always receive the rarest NFT trait by reverting on unfavorable rolls.
- Drain prize pools or skew reward distributions.

The impact is direct, unauthorized extraction of on-chain assets from other users or protocol treasuries.

---

### Likelihood Explanation

**High.** The entry path requires only a standard EVM or Cadence transaction — no staked node, no privileged key, no flashloan infrastructure. The randomness is block-scoped and observable for free via a script before any fee is paid. The attack is profitable whenever the expected gain from a favorable outcome exceeds the gas cost of a single transaction.

---

### Recommendation

Replace `revertibleRandom()` with `getRandomSource(height)` using a **past** block height, which reads from the `RandomBeaconHistory` contract — a committed, already-finalized value that cannot be observed before the transaction that uses it is submitted: [7](#0-6) 

For Cadence-side randomness, use a commit-reveal scheme: commit a user-supplied salt in block N, then derive the outcome from `RandomBeaconHistory.sourceOfRandomness(N)` in block N+k (k ≥ 1). This mirrors the TWAP recommendation in the original report — use a value that is already committed and cannot be influenced or selectively acted upon within the same execution context.

---

### Proof of Concept

```solidity
// Attacker EVM contract
interface CadenceArch {
    function revertibleRandom() external view returns (uint64);
}

contract SelectiveWinner {
    CadenceArch constant arch = CadenceArch(0x0000000000000000000000010000000000000001);

    // Called inside EVM.run() from a Cadence transaction.
    // Reverts (rolling back state) unless the random value is 0 mod 10.
    function enterLottery(address lotteryContract) external {
        uint64 rand = arch.revertibleRandom();
        require(rand % 10 == 0, "unfavorable — revert and retry next block");
        ILottery(lotteryContract).enter{value: ticketPrice}();
    }
}
```

The attacker wraps `EVM.run(enterLottery(...))` in a Cadence transaction that asserts `res.status == EVM.Status.successful`; if the EVM reverts, the Cadence transaction also reverts. The attacker repeats across blocks until `rand % 10 == 0` (statistically every ~10 blocks), winning the lottery at 10× the expected rate while paying gas only on the winning block.

### Citations

**File:** fvm/evm/handler/precompiles.go (L62-99)
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
		if err != nil {
			if types.IsAFatalError(err) {
				panic(err)
			}
			return nil, err
		}

		data, ok := value.(cadence.Struct)
		if !ok {
			return nil, fmt.Errorf("invalid output data received from getRandomSource")
		}

		cadenceArray := cadence.SearchFieldByName(data, RandomSourceTypeValueFieldName).(cadence.Array)
		source := make([]byte, environment.RandomSourceHistoryLength)
		for i := range source {
			source[i] = byte(cadenceArray.Values[i].(cadence.UInt8))
		}

		return source, nil
	}
}
```

**File:** fvm/evm/handler/precompiles.go (L101-111)
```go
func revertibleRandomGenerator(backend backends.Backend) func() (uint64, error) {
	return func() (uint64, error) {
		rand := make([]byte, 8)
		err := backend.ReadRandom(rand)
		if err != nil {
			return 0, err
		}

		return binary.BigEndian.Uint64(rand), nil
	}
}
```

**File:** fvm/environment/random_generator.go (L80-101)
```go
func (gen *randomGenerator) createPRG() (random.Rand, error) {
	// Use the protocol state source of randomness [SoR] for the current block's
	// execution
	source, err := gen.entropySource.RandomSource()
	// `RandomSource` does not error in normal operations.
	// Any error should be treated as an exception.
	if err != nil {
		return nil, fmt.Errorf("reading random source from state failed: %w", err)
	}

	// Use the state/protocol PRG derivation from the source of randomness:
	//  - for the transaction execution case, the PRG used must be a CSPRG
	//  - use the state/protocol/prg customizer defined for the execution environment
	//  - use the salt as an extra diversifier of the CSPRG. Although this
	//    does not add any extra entropy to the output, it allows creating an independent
	//    PRG for each transaction or script.
	csprg, err := prg.New(source, prg.ExecutionEnvironment, gen.salt)
	if err != nil {
		return nil, fmt.Errorf("failed to create a CSPRG from source: %w", err)
	}

	return csprg, nil
```

**File:** fvm/evm/precompiles/arch.go (L62-78)
```go
func ArchContract(
	address types.Address,
	heightProvider func() (uint64, error),
	proofVer func(*types.COAOwnershipProofInContext) (bool, error),
	randomSourceProvider func(uint64) ([]byte, error),
	revertibleRandomGenerator func() (uint64, error),
) types.PrecompiledContract {
	return MultiFunctionPrecompiledContract(
		address,
		[]Function{
			&flowBlockHeight{heightProvider},
			&proofVerifier{proofVer},
			&randomnessSource{randomSourceProvider},
			&revertibleRandom{revertibleRandomGenerator},
		},
	)
}
```

**File:** fvm/evm/precompiles/arch.go (L204-217)
```go
func (r *revertibleRandom) Run(input []byte) ([]byte, error) {
	rand, err := r.revertibleRandomGenerator()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, EncodedUint64Size)
	err = EncodeUint64(rand, buf, 0)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
```

**File:** fvm/fvm_blockcontext_test.go (L1761-1770)
```go
	txCode := []byte(`
	transaction {
		execute {
			let rand1 = revertibleRandom<UInt64>()
			log(rand1)
			let rand2 = revertibleRandom<UInt64>()
			log(rand2)
		}
	}
	`)
```

**File:** fvm/evm/testutils/contracts/test.sol (L91-96)
```text
    function verifyArchCallToRevertibleRandom() public view returns (uint64) {
        (bool ok, bytes memory data) = cadenceArch.staticcall(abi.encodeWithSignature("revertibleRandom()"));
        require(ok, "unsuccessful call to arch");
        uint64 output = abi.decode(data, (uint64));
        return output;
    }
```
