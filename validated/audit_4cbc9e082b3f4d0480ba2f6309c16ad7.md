[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** external-crates/move/crates/move-core-types/src/parsing/parser.rs (L16-17)
```rust
const MAX_TYPE_DEPTH: u64 = 128;
const MAX_TYPE_NODE_COUNT: u64 = 256;
```

**File:** external-crates/move/crates/move-core-types/src/parsing/parser.rs (L197-203)
```rust
    fn parse_type_impl(&mut self, depth: u64) -> Result<ParsedType> {
        self.count += 1;

        if depth > MAX_TYPE_DEPTH || self.count > MAX_TYPE_NODE_COUNT {
            bail!("Type exceeds maximum nesting depth or node count")
        }

```

**File:** external-crates/move/crates/move-core-types/src/parsing/parser.rs (L221-240)
```rust
            (tok @ (TypeToken::Ident | TypeToken::AddressIdent), contents) => {
                let fq_name = self.parse_fq_name_impl(tok, contents)?;
                let type_args = match self.peek_tok() {
                    Some(TypeToken::Lt) => {
                        self.advance(TypeToken::Lt)?;
                        let type_args = self.parse_list(
                            |parser| parser.parse_type_impl(depth + 1),
                            TypeToken::Comma,
                            TypeToken::Gt,
                            true,
                        )?;
                        self.advance(TypeToken::Gt)?;
                        if type_args.is_empty() {
                            bail!("expected at least one type argument")
                        }
                        type_args
                    }
                    _ => vec![],
                };
                ParsedType::Struct(ParsedStructType { fq_name, type_args })
```
