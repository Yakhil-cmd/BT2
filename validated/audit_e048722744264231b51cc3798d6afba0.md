### Title
Precision loss and potential overflow in consensus liquidity reward splitting - ([File: kaiax/staking/staking_info.go])

### Summary
The `Split` function in `kaiax/staking/staking_info.go` incorrectly converts `uint64` staking amounts to `int64` when creating `big.Int` objects for reward distribution calculations. This can lead to negative values or incorrect ratios if a validator's staking amount exceeds the `int64` maximum value (approx. 9.22 KAIA). Additionally, the calculation order `(clAmountBig * amount) / totalAmount` causes precision loss for small reward amounts because it performs division before subtraction, potentially resulting in zero rewards for consensus liquidity (CL) participants.

### Finding Description
In the Kaia blockchain, rewards are distributed between a validator's main staking address (CN) and their consensus liquidity (CL) pool based on their relative staking amounts. The `Split` function is responsible for this calculation.

1. **Unsafe Type Conversion**:
The function converts `uint64` staking amounts to `int64` using `big.NewInt(int64(c.StakingAmount))`. [1](#0-0) 
Staking amounts in the `StakingInfo` struct are stored in KAIA units (1 KAIA = $10^{18}$ kei). [2](#0-1) 
The maximum value of a signed `int64` is $2^{63}-1 \approx 9.22 \times 10^{18}$. If a validator stakes more than 9.22 KAIA, the `int64` conversion will overflow, making the value negative in the `big.Int` representation. This corrupts the `totalAmount` and the resulting reward ratio.

2. **Precision Loss**:
The reward is split using the formula: `clAmount = (clAmountBig * reward) / totalAmount`. [3](#0-2) 
Because the division is performed on the product of the reward and the CL stake, if the reward amount is small relative to the total stake, the result can truncate to zero even if the CL portion should have received a share. The remainder is then assigned to the CN address. [4](#0-3) 

### Impact Explanation
- **Asset Misallocation**: If the `int64` overflow occurs, the `totalAmount` calculation becomes invalid. This can cause the `clAmount` to be extremely large (if `totalAmount` becomes small or negative) or zero, leading to unauthorized transfer of rewards or protocol-level accounting failures.
- **Reward Theft/Loss**: Small reward amounts that should be shared with CL participants will be consistently rounded down to zero and awarded entirely to the validator's reward address (CN). This violates the KIP-226 invariant that rewards should be proportional to staking amounts.
- **Consensus Divergence**: Since reward distribution affects account balances, any node that calculates these values differently (e.g., due to different architecture handling of the overflow) would result in a state root mismatch and chain split.

### Likelihood Explanation
The likelihood is high for the precision loss, as it occurs every time a small block reward is distributed. The likelihood for the `int64` overflow is medium-to-high, as validators are expected to stake significantly more than 9.22 KAIA in production environments (the default minimum stake is often millions of KAIA).

### Recommendation
1. Use `new(big.Int).SetUint64()` instead of `big.NewInt(int64())` to safely handle the full range of `uint64` staking amounts.
2. Implement a remainder-aware distribution or ensure the reward amount is scaled before division to minimize precision loss.

### Proof of Concept
If a validator has:
- `cnStakingAmount` = $10 \times 10^{18}$ (10 KAIA)
- `clStakingAmount` = $10 \times 10^{18}$ (10 KAIA)

The code executes:
```go
cnAmountBig := big.NewInt(int64(10e18)) // Overflow! 10e18 > math.MaxInt64
// int64(10e18) becomes -8446744073709551616
```
The `totalAmount` will be calculated as a negative number or an incorrect small positive number depending on the specific overflow values, causing the `Div` operation in the reward split to produce an invalid `clAmount`.

For precision loss, if `reward` = 100 kei, `clAmountBig` = 1 KAIA, and `totalAmount` = 1000 KAIA:
`clAmount = (1e18 * 100) / 1000e18 = 0`.
The CL participants receive 0, and the CN receives 100, despite the CL having a valid share.

### Citations

**File:** kaiax/staking/staking_info.go (L47-48)
```go
	// Staking amounts of each staking contracts, in KAIA, rounded down. Does not include CL staking amounts.
	StakingAmounts []uint64 `json:"councilStakingAmounts"`
```

**File:** kaiax/staking/staking_info.go (L175-176)
```go
		cnAmountBig = big.NewInt(int64(c.StakingAmount))
		clAmountBig = big.NewInt(int64(c.CLStakingInfo.CLStakingAmount))
```

**File:** kaiax/staking/staking_info.go (L180-181)
```go
	clAmount := new(big.Int).Mul(clAmountBig, amount)
	clAmount = clAmount.Div(clAmount, totalAmount)
```

**File:** kaiax/staking/staking_info.go (L184-184)
```go
	cnAmount := big.NewInt(0).Sub(amount, clAmount)
```
