### Title
Unauthenticated `governance_vote` RPC API Allows Any External Caller to Queue Governance Parameter Changes on Behalf of the Node — (`kaiax/gov/headergov/impl/api.go`)

---

### Summary

The `governance_vote` JSON-RPC method is registered as `Public: true` on the HTTP/WS endpoint but performs no caller authentication. It unconditionally uses the node's own address (`api.h.nodeAddress`) as the voter. Any external client with RPC access can queue arbitrary governance parameter changes (e.g., `reward.mintingamount`, `governance.governingnode`, `reward.ratio`) that will be written into block headers when the node next proposes a block, and ratified at the epoch boundary — permanently altering reward distribution or transferring governance authority.

---

### Finding Description

**Root cause — no caller authentication in `Vote()`:** [1](#0-0) 

```go
func (api *headerGovAPI) Vote(name string, value any) (string, error) {
    var (
        voter     = api.h.nodeAddress   // ← always the node's own address
        ...
    )
    if gMode == "single" && voter != gp.GoverningNode {
        return "", ErrVotePermissionDenied
    }
    ...
    api.h.PushMyVotes(vote)   // ← appended unconditionally, no cap
```

The `voter` is hardcoded to `api.h.nodeAddress`. There is no check that the RPC caller is the node operator. The permission gate `voter != gp.GoverningNode` only fires in `single` mode when the node is **not** the governing node — meaning it passes silently when the node **is** the governing node. In `none` mode the gate is skipped entirely.

**API is publicly exposed:** [2](#0-1) 

`Public: true` exposes the method on the HTTP/WS endpoint, not just IPC/admin.

**`PushMyVotes` has no cap:** [3](#0-2) 

```go
func (h *headerGovModule) PushMyVotes(vote headergov.VoteData) {
    h.mu.Lock()
    defer h.mu.Unlock()
    h.myVotes = append(h.myVotes, vote)
}
```

**Vote is written into the next proposed block header:** [4](#0-3) 

`PrepareHeader` calls `peekMyVote()` and writes `header.Vote`. Peer nodes' `VerifyVote` accepts the vote as legitimate because the voter is the block proposer and is in the council. [5](#0-4) 

**Ratification at epoch boundary changes protected chain state:** [6](#0-5) 

At every epoch block the ratified governance data is persisted and takes effect for the next epoch.

---

### Impact Explanation

An external attacker with HTTP/WS access to the governing node (in `single` mode) or any GC node (in `none` mode) can:

1. **Stop all block rewards**: queue `reward.mintingamount = 0`. `FinalizeState` distributes `spec.Rewards` derived from `MintingAmount`; setting it to zero eliminates all minted KAIA per block. [7](#0-6) 

2. **Redirect reward distribution**: queue `reward.ratio = "100/0/0"` to funnel all minted tokens to validators and away from KIF/KEF funds, or vice versa. [8](#0-7) 

3. **Transfer governance authority**: queue `governance.governingnode = <attacker_address>` (in `none` mode, where any GC member can vote). Once ratified, the attacker's node becomes the sole authorized voter.

These are all protected chain-state changes: unauthorized reward distribution alteration and governance privilege escalation.

---

### Likelihood Explanation

- The `governance` namespace is `Public: true` — reachable over HTTP/WS without any credential.
- No authentication token, signature, or session is required.
- The attack is a single JSON-RPC call; no on-chain funds or keys are needed.
- In `none` mode (used in private/enterprise deployments), every GC node is a target. In `single` mode, only the governing node's endpoint needs to be reachable.
- The `pendingRequestLimit` of 200,000 concurrent requests means the attacker can flood `myVotes` before the operator notices. [9](#0-8) 

---

### Recommendation

1. **Restrict `governance_vote` to the admin/IPC endpoint**: change `Public: false` in the API registration, or move it to a separate admin-only namespace. [10](#0-9) 

2. **Authenticate the caller**: require the caller to sign a challenge with the node's private key, or verify the request originates from the local IPC socket.

3. **Cap `myVotes`**: enforce a maximum queue length in `PushMyVotes` to bound memory growth regardless of authentication. [3](#0-2) 

---

### Proof of Concept

```bash
# Step 1: Any external caller queues a vote to zero out block rewards
curl "http://<governing-node-rpc>:8551" -X POST \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"governance_vote",
           "params":["reward.mintingamount","0"]}'
# Returns success: "Your vote is prepared..."

# Step 2: The node proposes a block → PrepareHeader writes header.Vote
# Step 3: VerifyVote on peers accepts it (voter == proposer, voter in council)
# Step 4: At the next epoch block the vote is ratified
# Step 5: From (k+1)*epoch onward, MintingAmount == 0 → no block rewards distributed
```

The same call pattern applies to `reward.ratio`, `governance.governingnode`, or `istanbul.committeesize` — all governance parameters that alter reward distribution or chain authority without any on-chain transaction or privileged key.

### Citations

**File:** kaiax/gov/headergov/impl/api.go (L13-22)
```go
func (h *headerGovModule) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: "governance",
			Version:   "1.0",
			Service:   NewHeaderGovAPI(h),
			Public:    true,
		},
	}
}
```

**File:** kaiax/gov/headergov/impl/api.go (L53-82)
```go
func (api *headerGovAPI) Vote(name string, value any) (string, error) {
	var (
		voter     = api.h.nodeAddress
		nextBlock = api.h.Chain.CurrentBlock().NumberU64() + 1
		gp        = api.h.GetParamSet(nextBlock)
		gMode     = gp.GovernanceMode
	)

	if gMode == "single" && voter != gp.GoverningNode {
		return "", ErrVotePermissionDenied
	}

	vote := headergov.NewVoteData(voter, name, value)
	if vote == nil {
		return "", ErrInvalidKeyValue
	}

	if gov.DeprecatedAt(vote.Name(), api.h.ChainConfig.Rules(new(big.Int).SetUint64(nextBlock))) {
		return "", ErrDeprecatedVote
	}

	err := api.h.checkConsistency(nextBlock, vote)
	if err != nil {
		return "", err
	}

	// TODO-kaiax: add removevalidator vote check

	api.h.PushMyVotes(vote)
	return "(kaiax) Your vote is prepared. It will be put into the block header or applied when your node generates a block as a proposer. Note that your vote may be duplicate.", nil
```

**File:** kaiax/gov/headergov/impl/init.go (L183-188)
```go
func (h *headerGovModule) PushMyVotes(vote headergov.VoteData) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.myVotes = append(h.myVotes, vote)
}
```

**File:** kaiax/gov/headergov/impl/header.go (L30-39)
```go
func (h *headerGovModule) PrepareHeader(header *types.Header) error {
	// if this node has a vote waiting to be casted, put Vote field.
	if vote, ok := h.peekMyVote(); ok {
		voteBytes, err := vote.ToVoteBytes()
		if err != nil {
			return err
		}
		header.Vote = voteBytes
		logger.Debug("Prepare header with vote", "num", header.Number.Uint64(), "vote", hexutil.Encode(header.Vote))
	}
```

**File:** kaiax/gov/headergov/impl/header.go (L61-99)
```go
func (h *headerGovModule) VerifyVote(header *types.Header) error {
	if len(header.Vote) == 0 {
		return nil
	}

	var (
		vb       headergov.VoteBytes = header.Vote
		blockNum                     = header.Number.Uint64()
	)

	vote, err := vb.ToVoteData()
	if err != nil {
		logger.Error("ToVoteData error", "num", blockNum, "vote", vb, "err", err)
		return err
	}

	if gov.DeprecatedAt(vote.Name(), h.ChainConfig.Rules(header.Number)) {
		logger.Error("Vote is deprecated", "num", blockNum, "name", vote.Name())
		return ErrDeprecatedVote
	}

	council, err := h.ValSet.GetCouncil(blockNum)
	if err != nil {
		return err
	}

	// check if the voter is in council
	if !slices.Contains(council, vote.Voter()) {
		return ErrInvalidKeyValue
	}

	// check if Voter is the block proposer.
	author, err := h.Chain.Sealer().Author(header)
	if err != nil {
		return err
	}
	if author != vote.Voter() {
		return ErrInvalidVoter
	}
```

**File:** kaiax/gov/headergov/impl/execution.go (L57-63)
```go
func (h *headerGovModule) HandleGov(blockNum uint64, gov headergov.GovData) error {
	h.AddGov(blockNum, gov)

	data := h.GovBlockNums()
	WriteGovDataBlockNums(h.ChainKv, data)
	return nil
}
```

**File:** kaiax/reward/impl/blockstate.go (L53-56)
```go
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
	return nil
```

**File:** kaiax/reward/impl/getter.go (L344-347)
```go
	validators, kif, kef := config.RewardRatio.Split(minted)
	proposer, stakers := config.Kip82Ratio.Split(validators)
	ratioRemainder := calcRemainder(minted, proposer, stakers, kif, kef)
	kif.Add(kif, ratioRemainder)
```

**File:** networks/rpc/server.go (L47-49)
```go
	// pendingRequestLimit is a limit for concurrent RPC method calls
	pendingRequestLimit = 200000
)
```
