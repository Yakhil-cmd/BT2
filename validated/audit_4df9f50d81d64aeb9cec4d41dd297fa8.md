### Title
Missing Challenge Submission for Detected Chunk Faults — (`engine/verification/verifier/engine.go`)

### Summary
When the Verification Node's chunk verifier detects provable execution fraud — a non-matching final state commitment, an invalid verifiable chunk, or an invalid events collection — the verifier engine is supposed to raise a challenge against the offending Execution Node. Instead, three `// TODO raise challenge` stubs silently return `nil`, discarding the detected fault without reporting it to the network. This is the direct Flow analog of the original report's pattern: a critical security enforcement action is replaced by a TODO comment, leaving the system without the intended protection.

### Finding Description

In `engine/verification/verifier/engine.go`, the `verify()` function handles chunk fault errors returned by `ChunkVerifier.Verify()`. Three fault types that represent provable Execution Node misbehavior are handled with identical stubs:

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
``` [1](#0-0) 

Each of these cases returns `nil` (no error) before the result-approval generation block is reached, so the Verification Node neither approves the fraudulent result nor raises a challenge against it. The fraud is detected, logged, and then silently discarded.

The `ChunkVerifier.verifyTransactionsInContext()` function that produces these faults also carries three analogous `// TODO` stubs for checks that are not yet enforced:

```go
// TODO check collection hash to match
// TODO check datapack hash to match
// TODO check the number of transactions and computation used
``` [2](#0-1) 

Additionally, `seal_validator.go` contains a related incomplete guard — emergency sealing, which allows seals to be constructed with fewer verifier approvals than the normal threshold, is explicitly marked as a temporary BFT bypass that has not been removed:

```go
// Emergency sealing is a _temporary_ fallback ...
// TODO: remove this fallback for BFT
emergencySealed = true
``` [3](#0-2) 

### Impact Explanation

The challenge mechanism is the protocol's primary response to detected Execution Node fraud. Without it:

1. A malicious Execution Node can submit an execution result with a fabricated final state commitment (encoding unauthorized token mints, unauthorized account mutations, or arbitrary state corruption).
2. Assigned Verification Nodes will detect the fraud via `CFNonMatchingFinalState` or `CFInvalidEventsCollection`.
3. Because the challenge path is unimplemented, no fraud proof is broadcast to Consensus Nodes, no slashing is triggered, and the fraudulent result remains in the candidate-seal pipeline.
4. Combined with the emergency-sealing fallback (which permits sealing below the normal approval threshold), the fraudulent result can be sealed into the canonical chain without any Verification Node having approved it through the normal path.

The concrete on-chain impact is unauthorized mutation of execution state — including cross-VM asset loss and unauthorized account balance changes — that bypasses the verification layer entirely.

### Likelihood Explanation

The entry path requires a malicious or compromised Execution Node, which is a staked protocol participant. While this raises the bar above a fully unprivileged attacker, the Execution Node role is the only role that produces execution results, and the entire purpose of the Verification layer is to guard against exactly this threat model. The missing challenge code is reachable on every block that contains a fraudulent chunk, and the TODO comments confirm the gap is known and unresolved.

### Recommendation

1. Implement the challenge submission in each `// TODO raise challenge` branch of `verify()` in `engine/verification/verifier/engine.go`. The challenge should broadcast a `ChunkFault` (or equivalent fraud proof) to Consensus Nodes so they can reject the fraudulent result and initiate slashing.
2. Remove or gate the emergency-sealing fallback in `module/validation/seal_validator.go` behind an explicit, time-bounded protocol flag, and track its removal as a hard prerequisite for BFT guarantees.
3. Implement the three skipped integrity checks in `module/chunks/chunkVerifier.go` (collection hash, data-pack hash, transaction/computation count).

### Proof of Concept

1. A malicious Execution Node produces an `ExecutionResult` for block B with a fabricated `FinalState` commitment that encodes an unauthorized FLOW token mint.
2. The result is incorporated into a candidate block and propagated to the network.
3. An assigned Verification Node receives the corresponding `VerifiableChunkData` and calls `ChunkVerifier.Verify()`.
4. `verifyTransactionsInContext()` re-executes the chunk locally, computes the correct end state, and finds it does not match the claimed `FinalState` → returns `chmodels.NewCFNonMatchingFinalState(...)`.
5. `verify()` in `engine/verification/verifier/engine.go` matches the `*chmodels.CFNonMatchingFinalState` case, logs a warning, and returns `nil` — no challenge is raised, no approval is withheld in a way that is visible to Consensus Nodes.
6. With emergency sealing active, Consensus Nodes can seal the fraudulent result once the minimum `RequireApprovalsForSealVerification` threshold is met (possibly zero, depending on configuration), finalizing the unauthorized state change on-chain. [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** engine/verification/verifier/engine.go (L196-233)
```go
	spockSecret, err := e.chVerif.Verify(vc)
	span.End()

	if err != nil {
		// any error besides a ChunkFaultError is a system error
		if !chmodels.IsChunkFaultError(err) {
			return fmt.Errorf("cannot verify chunk: %w", err)
		}

		// if any fault found with the chunk
		switch chFault := err.(type) {
		case *chmodels.CFMissingRegisterTouch:
			log.Warn().
				Str("chunk_fault_type", "missing_register_touch").
				Str("chunk_fault", chFault.Error()).
				Msg("chunk fault found, could not verify chunk")
			// still create approvals for this case
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

**File:** module/chunks/chunkVerifier.go (L359-364)
```go
	// TODO check if exec node provided register touches that was not used (no read and no update)
	// check if the end state commitment mentioned in the chunk matches
	// what the partial trie is providing.
	if flow.StateCommitment(expEndStateComm) != endState {
		return nil, chmodels.NewCFNonMatchingFinalState(flow.StateCommitment(expEndStateComm), endState, chIndex, execResID)
	}
```

**File:** module/validation/seal_validator.go (L309-322)
```go
		requireApprovalsForSealConstruction := s.sealingConfigsGetter.RequireApprovalsForSealConstructionDynamicValue()
		requireApprovalsForSealVerification := s.sealingConfigsGetter.RequireApprovalsForSealVerificationConst()
		if uint(numberApprovers) < requireApprovalsForSealConstruction {
			if uint(numberApprovers) >= requireApprovalsForSealVerification {
				// Emergency sealing is a _temporary_ fallback to reduce the probability of
				// sealing halts due to bugs in the verification nodes, where they don't
				// approve a chunk even though they should (false-negative).
				// TODO: remove this fallback for BFT
				emergencySealed = true
			} else {
				return engine.NewInvalidInputErrorf("chunk %d has %d approvals but require at least %d",
					chunk.Index, numberApprovers, requireApprovalsForSealVerification)
			}
		}
```
