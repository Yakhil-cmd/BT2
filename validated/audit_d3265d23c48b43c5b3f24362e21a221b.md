[1](#0-0) [2](#0-1)

### Citations

**File:** third_party/move/move-bytecode-verifier/src/loop_summary.rs (L41-52)
```rust
/// A disjoint-set data structure used when collapsing loops down to single nodes in the summary
/// graph while remembering their loop nesting depth (how many levels of nesting are contained
/// within them)
pub struct LoopPartition {
    /// The parent relationship in the disjoint-set.  The transitive closure of this type maps a
    /// node to its representative.
    parents: NodeMap<NodeId>,

    /// The nesting depth of (collapsed) nodes in the summary graph.  Nodes that are uncollapsed
    /// (not in any loop) have a depth of 0.  Initially, all nodes are uncollapsed.
    depths: NodeMap<u16>,
}
```

**File:** third_party/move/move-bytecode-verifier/src/loop_summary.rs (L76-84)
```rust
        let num_blocks = cfg.num_blocks() as usize;

        // Fields in LoopSummary that are filled via a depth-first traversal of `cfg`.
        let mut blocks = vec![0; num_blocks];
        let mut descs = vec![0; num_blocks];
        let mut backs = vec![vec![]; num_blocks];
        let mut preds = vec![vec![]; num_blocks];

        let mut next_node = NodeId(0);
```
