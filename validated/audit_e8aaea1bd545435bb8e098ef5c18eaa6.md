[1](#0-0)

### Citations

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/sigma_protocol_utils.move (L56-58)
```text
    public(friend) fun deserialize_compressed_points(points_bytes: vector<vector<u8>>): vector<CompressedRistretto> {
        points_bytes.map(|bytes| new_compressed_point_from_bytes(bytes).extract())
    }
```
