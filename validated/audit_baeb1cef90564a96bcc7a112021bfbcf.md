[1](#0-0)

### Citations

**File:** aptos-move/block-executor/src/captured_reads.rs (L72-79)
```rust
/// The enum captures the state that the transaction execution extracted from
/// a read callback to block executor, in order to be validated by Block-STM.
/// The captured state is fine-grained, e.g. it distinguishes between reading
/// a full value, and other kinds of reads that may access only the metadata
/// information, or check whether data exists at a given key.
#[derive(Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = ""), PartialEq(bound = ""))]
pub(crate) enum DataRead<V> {
```
