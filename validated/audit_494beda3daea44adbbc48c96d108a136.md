No vulnerability found for this question.

The reported bug class is specific to Merkle-tree implementations where a leaf's serialized encoding (`keccak256(abi.encode(destination, value))`, 64 bytes) has the same byte-length as an internal node's encoding (`keccak256(abi.encode(a, b))`, also 64 bytes), enabling a subtree hash to be replayed as a fraudulent leaf. `c-kzg-4844` contains no Merkle-tree structure, no recursive hashing of same-length leaf/parent pairs, and no proof mechanism verifying inclusion via sibling hashing at all.

The only hash-based domain-separated structures in this repo are the Fiat-Shamir challenge builders `compute_challenge` [1](#0-0) , `compute_r_powers_for_verify_kzg_proof_batch` [2](#0-1) , and `compute_verify_cell_kzg_proof_batch_challenge` [3](#0-2) . These construct a single flat byte buffer, prefixed with a fixed 16-byte domain-separator string and explicit `uint64` count/length fields for every variable-size section (e.g. `num_commitments`, `num_cells`, `FIELD_ELEMENTS_PER_BLOB`), before hashing with `blst_sha256`. This means there is no ambiguity analogous to the Merkle leaf/parent collision: the encoding is not self-similar or recursively nested (there is no "leaf vs. subtree" concept), and the explicit length-prefixing of every field prevents two semantically different logical inputs from producing an identical byte-serialization, which is the root cause exploited in the original finding. [4](#0-3)

### Citations

**File:** src/eip4844/eip4844.c (L34-48)
```c
/** Length of the domain string. */
#define DOMAIN_STR_LENGTH 16

/* Input size to the Fiat-Shamir challenge computation. */
#define CHALLENGE_INPUT_SIZE (DOMAIN_STR_LENGTH + 16 + BYTES_PER_BLOB + BYTES_PER_COMMITMENT)

////////////////////////////////////////////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////////////////////////////////////////////

/** The domain separator for the Fiat-Shamir protocol. */
static const char *FIAT_SHAMIR_PROTOCOL_DOMAIN = "FSBLOBVERIFY_V1_";

/** The domain separator for verify_blob_kzg_proof's random challenge. */
static const char *RANDOM_CHALLENGE_DOMAIN_VERIFY_BLOB_KZG_PROOF_BATCH = "RCKZGBATCH___V1_";
```

**File:** src/eip4844/eip4844.c (L147-178)
```c
void compute_challenge(fr_t *eval_challenge_out, const Blob *blob, const g1_t *commitment) {
    Bytes32 eval_challenge;
    uint8_t bytes[CHALLENGE_INPUT_SIZE];

    /* Pointer tracking `bytes` for writing on top of it */
    uint8_t *offset = bytes;

    /* Copy domain separator */
    memcpy(offset, FIAT_SHAMIR_PROTOCOL_DOMAIN, DOMAIN_STR_LENGTH);
    offset += DOMAIN_STR_LENGTH;

    /* Copy polynomial degree (16-bytes, big-endian) */
    bytes_from_uint64(offset, 0);
    offset += sizeof(uint64_t);
    bytes_from_uint64(offset, FIELD_ELEMENTS_PER_BLOB);
    offset += sizeof(uint64_t);

    /* Copy blob */
    memcpy(offset, blob->bytes, BYTES_PER_BLOB);
    offset += BYTES_PER_BLOB;

    /* Copy commitment */
    bytes_from_g1((Bytes48 *)offset, commitment);
    offset += BYTES_PER_COMMITMENT;

    /* Make sure we wrote the entire buffer */
    assert(offset == bytes + CHALLENGE_INPUT_SIZE);

    /* Now let's create the challenge! */
    blst_sha256(eval_challenge.bytes, bytes, CHALLENGE_INPUT_SIZE);
    hash_to_bls_field(eval_challenge_out, &eval_challenge);
}
```

**File:** src/eip4844/eip4844.c (L597-680)
```c
static C_KZG_RET compute_r_powers_for_verify_kzg_proof_batch(
    fr_t *r_powers_out,
    const g1_t *commitments_g1,
    const fr_t *zs_fr,
    const fr_t *ys_fr,
    const g1_t *proofs_g1,
    size_t n
) {
    C_KZG_RET ret;
    uint8_t *bytes = NULL;
    blst_p1_affine *commitments_affine = NULL;
    blst_p1_affine *proofs_affine = NULL;
    Bytes32 r_bytes;
    fr_t r;

    size_t input_size = DOMAIN_STR_LENGTH + sizeof(uint64_t) + sizeof(uint64_t) +
                        (n *
                         (BYTES_PER_COMMITMENT + 2 * BYTES_PER_FIELD_ELEMENT + BYTES_PER_PROOF));
    ret = c_kzg_malloc((void **)&bytes, input_size);
    if (ret != C_KZG_OK) goto out;

    /* Allocate space for affine commitments and proofs */
    ret = c_kzg_malloc((void **)&commitments_affine, n * sizeof(blst_p1_affine));
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_malloc((void **)&proofs_affine, n * sizeof(blst_p1_affine));
    if (ret != C_KZG_OK) goto out;

    /* Batch convert commitments and proofs to affine */
    const blst_p1 *commitments_arg[2] = {commitments_g1, NULL};
    blst_p1s_to_affine(commitments_affine, commitments_arg, n);
    const blst_p1 *proofs_arg[2] = {proofs_g1, NULL};
    blst_p1s_to_affine(proofs_affine, proofs_arg, n);

    /* Pointer tracking `bytes` for writing on top of it */
    uint8_t *offset = bytes;

    /* Ensure that the domain string is the correct length */
    assert(strlen(RANDOM_CHALLENGE_DOMAIN_VERIFY_BLOB_KZG_PROOF_BATCH) == DOMAIN_STR_LENGTH);

    /* Copy domain separator */
    memcpy(offset, RANDOM_CHALLENGE_DOMAIN_VERIFY_BLOB_KZG_PROOF_BATCH, DOMAIN_STR_LENGTH);
    offset += DOMAIN_STR_LENGTH;

    /* Copy degree of the polynomial */
    bytes_from_uint64(offset, FIELD_ELEMENTS_PER_BLOB);
    offset += sizeof(uint64_t);

    /* Copy number of commitments */
    bytes_from_uint64(offset, n);
    offset += sizeof(uint64_t);

    for (size_t i = 0; i < n; i++) {
        /* Copy commitment */
        blst_p1_affine_compress(offset, &commitments_affine[i]);
        offset += BYTES_PER_COMMITMENT;

        /* Copy z */
        bytes_from_bls_field((Bytes32 *)offset, &zs_fr[i]);
        offset += BYTES_PER_FIELD_ELEMENT;

        /* Copy y */
        bytes_from_bls_field((Bytes32 *)offset, &ys_fr[i]);
        offset += BYTES_PER_FIELD_ELEMENT;

        /* Copy proof */
        blst_p1_affine_compress(offset, &proofs_affine[i]);
        offset += BYTES_PER_PROOF;
    }

    /* Now let's create the challenge! */
    blst_sha256(r_bytes.bytes, bytes, input_size);
    hash_to_bls_field(&r, &r_bytes);

    compute_powers(r_powers_out, &r, n);

    /* Make sure we wrote the entire buffer */
    assert(offset == bytes + input_size);

out:
    c_kzg_free(bytes);
    c_kzg_free(commitments_affine);
    c_kzg_free(proofs_affine);
    return ret;
}
```

**File:** src/eip7594/eip7594.c (L390-482)
```c
C_KZG_RET compute_verify_cell_kzg_proof_batch_challenge(
    fr_t *challenge_out,
    const Bytes48 *commitments_bytes,
    uint64_t num_commitments,
    const uint64_t *commitment_indices,
    const uint64_t *cell_indices,
    const Cell *cells,
    const Bytes48 *proofs_bytes,
    uint64_t num_cells
) {
    C_KZG_RET ret;
    uint8_t *bytes = NULL;
    Bytes32 r_bytes;

    /* Calculate the size of the data we're going to hash */
    size_t input_size = DOMAIN_STR_LENGTH                          /* The domain separator */
                        + sizeof(uint64_t)                         /* FIELD_ELEMENTS_PER_BLOB */
                        + sizeof(uint64_t)                         /* FIELD_ELEMENTS_PER_CELL */
                        + sizeof(uint64_t)                         /* num_commitments */
                        + sizeof(uint64_t)                         /* num_cells */
                        + (num_commitments * BYTES_PER_COMMITMENT) /* commitment_bytes */
                        + (num_cells * sizeof(uint64_t))           /* commitment_indices */
                        + (num_cells * sizeof(uint64_t))           /* cell_indices */
                        + (num_cells * BYTES_PER_CELL)             /* cells */
                        + (num_cells * BYTES_PER_PROOF);           /* proofs_bytes */

    /* Allocate space to copy this data into */
    ret = c_kzg_malloc((void **)&bytes, input_size);
    if (ret != C_KZG_OK) goto out;

    /* Pointer tracking `bytes` for writing on top of it */
    uint8_t *offset = bytes;

    /* Ensure that the domain string is the correct length */
    assert(strlen(RANDOM_CHALLENGE_DOMAIN_VERIFY_CELL_KZG_PROOF_BATCH) == DOMAIN_STR_LENGTH);

    /* Copy domain separator */
    memcpy(offset, RANDOM_CHALLENGE_DOMAIN_VERIFY_CELL_KZG_PROOF_BATCH, DOMAIN_STR_LENGTH);
    offset += DOMAIN_STR_LENGTH;

    /* Copy field elements per blob */
    bytes_from_uint64(offset, FIELD_ELEMENTS_PER_BLOB);
    offset += sizeof(uint64_t);

    /* Copy field elements per cell */
    bytes_from_uint64(offset, FIELD_ELEMENTS_PER_CELL);
    offset += sizeof(uint64_t);

    /* Copy number of commitments */
    bytes_from_uint64(offset, num_commitments);
    offset += sizeof(uint64_t);

    /* Copy number of cells */
    bytes_from_uint64(offset, num_cells);
    offset += sizeof(uint64_t);

    for (size_t i = 0; i < num_commitments; i++) {
        /* Copy commitment */
        memcpy(offset, &commitments_bytes[i], BYTES_PER_COMMITMENT);
        offset += BYTES_PER_COMMITMENT;
    }

    for (size_t i = 0; i < num_cells; i++) {
        /* Copy row id */
        bytes_from_uint64(offset, commitment_indices[i]);
        offset += sizeof(uint64_t);

        /* Copy column id */
        bytes_from_uint64(offset, cell_indices[i]);
        offset += sizeof(uint64_t);

        /* Copy cell */
        memcpy(offset, &cells[i], BYTES_PER_CELL);
        offset += BYTES_PER_CELL;

        /* Copy proof */
        memcpy(offset, &proofs_bytes[i], BYTES_PER_PROOF);
        offset += BYTES_PER_PROOF;
    }

    /* Make sure we wrote the entire buffer */
    assert(offset == bytes + input_size);

    /* Create the challenge hash */
    blst_sha256(r_bytes.bytes, bytes, input_size);

    /* Convert to BLS field element */
    hash_to_bls_field(challenge_out, &r_bytes);

out:
    c_kzg_free(bytes);
    return ret;
}
```
