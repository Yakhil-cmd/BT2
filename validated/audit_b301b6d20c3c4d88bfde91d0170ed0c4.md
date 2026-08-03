[1](#0-0) [2](#0-1)

### Citations

**File:** aptos-move/framework/aptos-framework/sources/account/rate_limiter.move (L21-29)
```text
    public fun initialize(capacity: u64, refill_interval: u64): RateLimiter {
        RateLimiter::TokenBucket {
            capacity,
            current_amount: capacity, // Start with a full bucket (full capacity of transactions allowed)
            refill_interval,
            last_refill_timestamp: timestamp::now_seconds(),
            fractional_accumulated: 0, // Start with no fractional accumulated
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/rate_limiter.move (L49-56)
```text
        if (limiter.current_amount + new_tokens >= limiter.capacity) {
            limiter.current_amount = limiter.capacity;
            limiter.fractional_accumulated = 0;
        } else {
            limiter.current_amount += new_tokens;
            // Update the fractional amount accumulated for the next refill cycle
            limiter.fractional_accumulated = accumulated_amount % limiter.refill_interval;
        };
```
