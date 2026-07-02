### Title
Missing On-Chain Challenge Mechanism for Detected Chunk Faults - (File: `engine/verification/verifier/engine.go`)

### Summary
When a Verification Node detects critical chunk faults proving a fraudulent execution result (e.g., `CFNonMatchingFinalState`, `CFInvalidVerifiableChunk`, `CFInvalidEventsCollection`), the protocol design requires raising an on-chain challenge to slash the misbehaving Execution Node. This mechanism is explicitly marked `// TODO raise challenge` but is entirely unimplemented. The node silently discards the detection and returns `nil`, leaving the misbehaving Execution Node with no on-chain accountability.

### Finding Description
In `engine/verification/verifier/engine.go`, the `verify` function processes chunk faults returned by `ChunkVerifier.Verify`. For the most security-critical fault types, the switch-case handler logs a warning and returns `nil` without submitting any on-chain challenge:

```go
case *chmodels.CFNonMatchingFinalState:
    // TODO raise challenge
    log.Warn()...
    return nil
case *chmodels.CFInvalidVerifiableChunk:
    // TODO raise challenge
    log.Error()...
    return nil
case *chmodels.CFInvalidEventsCollection:
    // TODO raise challenge
    log.Error()...
    return nil
```

The fault types `CFNonMatchingFinalState`, `CFInvalidVerifiableChunk`, and `CFInvalidEventsCollection` each represent provable, deterministic evidence that an Execution Node submitted a fraudulent `ExecutionResult`. The protocol's documented design requires that a Verification Node holding such proof broadcast an on-chain challenge (a slashing transaction) against the offending Execution Node's staked collateral. None of this is implemented.

Additionally, `module/chunks/chunkVerifier.go` carries three companion TODOs that are also unimplemented:

```go
// TODO check collection hash to match
// TODO check datapack hash to match
// TODO check the number of transactions and computation used
```

These missing pre-checks mean the verifier does not confirm that the collection provided in the `ChunkDataPack` matches the collection hash committed in the block before re-executing transactions, further weakening the integrity of the verification step.

### Impact Explanation
Flow's economic security model depends on Execution Nodes being slashed when they submit fraudulent `ExecutionResult`s. Without the challenge mechanism:

1. A malicious Execution Node can submit a fraudulent `ExecutionResult` (wrong `EndState`, wrong events, invalid chunk structure).
2. Verification Nodes detect the fraud, log it, and return `nil` — no result approval is emitted and no challenge is raised.
3. The fraudulent result is not sealed (no approvals), but the Execution Node's staked collateral is never at risk.
4. The economic disincentive for submitting fraudulent results is eliminated on-chain.

The staked tokens of misbehaving Execution Nodes that should be slashed are never touched, constituting a direct failure to enforce on-chain asset accountability. This is the exact analog of the external report: a documented on-chain calculation (slashing/challenge) is absent from the implementation.

### Likelihood Explanation
Any operator running a staked Execution Node can submit a fraudulent `ExecutionResult`. The entry path is fully reachable and requires no special privileges beyond holding an Execution Node stake. The `// TODO raise challenge` comments confirm the gap is known and unresolved. Likelihood is **Medium**: the attack requires a staked Execution Node but no quorum compromise, and the economic incentive to exploit it grows as the value secured by the protocol increases.

### Recommendation
Implement the challenge submission path for each `// TODO raise challenge` branch. When a Verification Node holds a `CFNonMatchingFinalState`, `CFInvalidVerifiableChunk`, or `CFInvalidEventsCollection` fault, it should:
1. Construct a signed on-chain challenge (slashing transaction) referencing the `ExecutionResultID`, `ChunkIndex`, and the computed vs. claimed state commitments.
2. Broadcast the challenge to Consensus Nodes via the existing conduit.
3. Implement the missing collection-hash, datapack-hash, and transaction-count pre-checks in `verifyTransactionsInContext` to ensure the challenge evidence is sound before submission.

### Proof of Concept
1. A malicious Execution Node executes block `B` and produces a fraudulent `ExecutionResult` `ER` where `Chunk[i].EndState = S_fraud ≠ S_correct`.
2. A Verification Node assigned to chunk `i` receives the `ChunkDataPack`, re-executes the transactions via `ChunkVerifier.Verify`, and computes `S_correct`.
3. `verifyTransactionsInContext` detects the mismatch at line ~362 of `module/chunks/chunkVerifier.go` and returns `CFNonMatchingFinalState`.
4. `engine/verification/verifier/engine.go` matches the `CFNonMatchingFinalState` case, logs a warning, and returns `nil` — no challenge is raised, no result approval is emitted.
5. The Execution Node's staked collateral is never at risk despite submitting provably fraudulent state. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** engine/verification/verifier/engine.go (L213-233)
```go
		case *chmodels.CFNonMatchingFinalState:
			// TODO raise challenge
			log.Warn().
				Str("chunk_fault_type", "final_state_mismatch").
				Str("chunk_fault", chFault.Error()).
				Msg("chunk fault found, could not verify chunk")
			return nil
		case *chmodels.CFInvalidVerifiableChunk:
			// TODO raise challenge
			log.Error().
				Str("chunk_fault_type", "invalid_verifiable_chunk").
				Str("chunk_fault", chFault.Error()).
				Msg("chunk fault found, could not verify chunk")
			return nil
		case *chmodels.CFInvalidEventsCollection:
			// TODO raise challenge
			log.Error().
				Str("chunk_fault_type", "invalid_event_collection").
				Str("chunk_fault", chFault.Error()).
				Msg("chunk fault found, could not verify chunk")
			return nil
```

**File:** module/chunks/chunkVerifier.go (L151-153)
```go
	// TODO check collection hash to match
	// TODO check datapack hash to match
	// TODO check the number of transactions and computation used
```

**File:** module/chunks/chunkVerifier.go (L360-364)
```go
	// check if the end state commitment mentioned in the chunk matches
	// what the partial trie is providing.
	if flow.StateCommitment(expEndStateComm) != endState {
		return nil, chmodels.NewCFNonMatchingFinalState(flow.StateCommitment(expEndStateComm), endState, chIndex, execResID)
	}
```

**File:** model/chunks/chunkFaults.go (L66-101)
```go
// CFNonMatchingFinalState is returned when the computed final state commitment
// (applying chunk register updates to the partial trie) doesn't match the one provided by the chunk
type CFNonMatchingFinalState struct {
	expected   flow.StateCommitment
	computed   flow.StateCommitment
	chunkIndex uint64
	execResID  flow.Identifier
}

var _ ChunkFaultError = (*CFNonMatchingFinalState)(nil)

func (cf CFNonMatchingFinalState) String() string {
	return fmt.Sprintf("final state commitment doesn't match, expected [%x] but computed [%x]", cf.expected, cf.computed)
}

func (cf CFNonMatchingFinalState) Error() string {
	return cf.String()
}

// ChunkIndex returns chunk index of the faulty chunk
func (cf CFNonMatchingFinalState) ChunkIndex() uint64 {
	return cf.chunkIndex
}

// ExecutionResultID returns the execution result identifier including the faulty chunk
func (cf CFNonMatchingFinalState) ExecutionResultID() flow.Identifier {
	return cf.execResID
}

// NewCFNonMatchingFinalState creates a new instance of Chunk Fault (NonMatchingFinalState)
func NewCFNonMatchingFinalState(expected flow.StateCommitment, computed flow.StateCommitment, chInx uint64, execResID flow.Identifier) *CFNonMatchingFinalState {
	return &CFNonMatchingFinalState{expected: expected,
		computed:   computed,
		chunkIndex: chInx,
		execResID:  execResID}
}
```
