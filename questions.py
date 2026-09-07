import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 20
# todo: the GitLab namespace/project path, for example group/project
SOURCE_REPO = 'ethereum/c-kzg-4844'
# todo: the name of the repository
REPO_NAME = 'c-kzg-4844'

run_number = os.environ.get('GITHUB_RUN_NUMBER', '0')


def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index"""
    return (int(run_number) - 1) % max_index + 1


def load_repository_urls():
    """Load repository URLs from repositories.json."""
    repo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repositories.json")
    if not os.path.exists(repo_file):
        return []

    try:
        with open(repo_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    return [url for url in data if isinstance(url, str) and url.strip()]


if run_number == "0":
    BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
    repository_urls = load_repository_urls()
    if repository_urls:
        run_index = get_cyclic_index(run_number, len(repository_urls))
        BASE_URL = repository_urls[run_index - 1]
    else:
        BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"


scope_files = [
    # =================================================================================
    # LENS: KZG PROOF SOUNDNESS, DETERMINISM AND MEMORY SAFETY (c-kzg-4844).
    # Every Ethereum client links this library to decide whether a blob, a commitment,
    # a proof or a set of cells is valid. Untrusted bytes enter through blob
    # transactions, blob sidecars and data-column sidecars that any user can publish;
    # honest nodes forward them straight into these functions. The files below sit on
    # the path from those bytes to one of three decisions: does `ok` equal the truth of
    # the pairing relation, does every node compute the same bytes and the same verdict,
    # and does every index and length derived from the input stay inside its buffer. A
    # question belongs here only if it can be closed by an equality between what the
    # attacker supplied and what the library returned.
    # =================================================================================
    # -- core: the umbrella translation unit and public header ---------------------------
    "src/ckzg.c",
    "src/ckzg.h",

    # -- core: byte <-> field / point conversion, arithmetic, MSM, pairings ---------------
    "src/common/alloc.c",
    "src/common/alloc.h",
    "src/common/bytes.c",
    "src/common/bytes.h",
    "src/common/ec.c",
    "src/common/ec.h",
    "src/common/fr.c",
    "src/common/fr.h",
    "src/common/lincomb.c",
    "src/common/lincomb.h",
    "src/common/ret.h",
    "src/common/utils.c",
    "src/common/utils.h",

    # -- core: EIP-4844 blob commitments, proofs, single and batch verification ----------
    "src/eip4844/blob.c",
    "src/eip4844/blob.h",
    "src/eip4844/eip4844.c",
    "src/eip4844/eip4844.h",

    # -- core: EIP-7594 cells, FK20 proofs, recovery, cell batch verification -------------
    "src/eip7594/cell.c",
    "src/eip7594/cell.h",
    "src/eip7594/eip7594.c",
    "src/eip7594/eip7594.h",
    "src/eip7594/fft.c",
    "src/eip7594/fft.h",
    "src/eip7594/fk20.c",
    "src/eip7594/fk20.h",
    "src/eip7594/poly.c",
    "src/eip7594/poly.h",
    "src/eip7594/recovery.c",
    "src/eip7594/recovery.h",

    # -- core: trusted setup parsing and derived tables (roots of unity, BRP, FK20) -------
    "src/setup/settings.h",
    "src/setup/setup.c",
    "src/setup/setup.h",

    # -- bindings: the layer that turns client-supplied arrays into C pointers and counts --
    "bindings/csharp/ckzg_wrap.c",
    "bindings/csharp/ckzg_wrap.h",
    "bindings/csharp/Ckzg.Bindings/Ckzg.Bindings.cs",
    "bindings/csharp/Ckzg.Bindings/Ckzg.cs",
    "bindings/elixir/native/src/ckzg_wrap.c",
    "bindings/elixir/lib/kzg.ex",
    "bindings/go/main.go",
    "bindings/java/ckzg_jni.c",
    "bindings/java/ckzg_jni.h",
    "bindings/java/src/main/java/ethereum/ckzg4844/CKZG4844JNI.java",
    "bindings/java/src/main/java/ethereum/ckzg4844/CKZGException.java",
    "bindings/java/src/main/java/ethereum/ckzg4844/CellsAndProofs.java",
    "bindings/java/src/main/java/ethereum/ckzg4844/ProofAndY.java",
    "bindings/nim/kzg.nim",
    "bindings/nim/kzg_abi.nim",
    "bindings/node.js/src/kzg.cxx",
    "bindings/node.js/lib/kzg.js",
    "bindings/node.js/lib/kzg.d.ts",
    "bindings/python/ckzg_wrap.c",
    "bindings/rust/src/lib.rs",
    "bindings/rust/src/bindings/mod.rs",
    "bindings/rust/src/bindings/serde.rs",
    "bindings/rust/src/ethereum_kzg_settings/mod.rs",
    "bindings/zig/src/root.zig",

    # =================================================================================
    # NOT AUDITED (excluded from every variant): src/test/**, tests/** reference vectors,
    # fuzz/**, every *_test.go / tests.py / *.test.ts / *Test.java / tests.zig /
    # ckzg_test.exs / tests.nim, bindings/*/test*, testFixtures and test_formats;
    # generated code (bindings/rust/src/bindings/generated.rs, the nimble/ copies of
    # kzg.nim and kzg_abi.nim); trusted_setup.txt and the .bin setup blobs; the blst
    # submodule; scripts/, audits/, Makefiles, build.zig, binding.gyp, Cargo/go/mix/
    # gradle/csproj/package files, Dockerfiles and every README. A defect in any of
    # these is only in scope when it is reachable from the audited code above.
    # =================================================================================
]


target_scopes = [
    "Critical. A SINGLE PROOF MUST VERIFY ONLY IF THE PAIRING RELATION HOLDS. `verify_kzg_proof` converts four caller byte arrays through `bytes_to_kzg_commitment`, `bytes_to_bls_field` (canonical check via `blst_scalar_fr_check`) and `bytes_to_kzg_proof`, then `verify_kzg_proof_impl` checks `e(C - [y]G1, G2) == e(pi, [s]G2 - [z]G2)` with `g2_values_monomial[1]`; `verify_blob_kzg_proof` derives `z` from `compute_challenge` (domain `FSBLOBVERIFY_V1_`, degree, blob bytes, compressed commitment) and `y` from `evaluate_polynomial_in_evaluation_form`, whose in-domain shortcut returns `poly[i]` on `fr_equal(x, brp_roots_of_unity[i])`. `validate_kzg_g1` accepts the point at infinity before the subgroup check. Probe every input where `ok` can be true while the polynomial identity is false: commitment or proof at infinity paired with a zero or chosen `y`; a `y_bytes` or `z_bytes` above the modulus; a challenge that lands exactly on a root of unity so the barycentric branch is skipped; a proof that only satisfies the equation because `g1_sub` or `g2_sub` negated the wrong side; a blob whose field elements are all zero. Identity: `*ok == true` if and only if `p(z) == y` for the polynomial committed by `commitment_bytes`, for every byte string the caller can pass.",

    "Critical. BATCH VERIFICATION MUST ACCEPT EXACTLY THE SET SINGLE VERIFICATION ACCEPTS. `verify_blob_kzg_proof_batch` short-circuits `n == 0` to true and `n == 1` to `verify_blob_kzg_proof`; for `n > 1` it computes per-blob challenges, `ys_fr`, then `compute_r_powers_for_verify_kzg_proof_batch` hashes `RCKZGBATCH___V1_`, degree, `n`, and each (compressed commitment, z, y, compressed proof) after `blst_p1s_to_affine`, and `verify_kzg_proof_batch` checks `e(sum r^i pi_i, [s]G2) == e(sum r^i (C_i - [y_i]) + sum r^i z_i pi_i, G2)` through `g1_lincomb_naive`. Show a batch where one invalid (blob, commitment, proof) triple verifies because another entry cancels it, or a batch whose verdict differs from verifying each entry alone: a proof or commitment at infinity whose affine compression feeds the transcript differently from `bytes_from_g1`; two identical entries whose `r` powers collide; a transcript that omits a field an attacker controls so `r` is predictable before the proof is chosen; an `n == 1` path that rejects what `n > 1` accepts or vice versa; a `C_minus_y` or `r_times_z` computed with the wrong index. Identity: `verify_blob_kzg_proof_batch(ok, ..., n)` == AND over i of `verify_blob_kzg_proof(ok_i, blobs[i], commitments[i], proofs[i])`, for every n and every byte string.",

    "Critical. A CELL BATCH MUST VERIFY ONLY IF EVERY (COMMITMENT, INDEX, CELL, PROOF) TUPLE IS VALID. `verify_cell_kzg_proof_batch` bounds `cell_indices[i] < CELLS_PER_EXT_BLOB` but never bounds `num_cells`, never rejects duplicate `(commitment, cell_index)` pairs, then `deduplicate_commitments` rewrites `unique_commitments` and `commitment_indices` by byte equality (so two encodings of one point are two commitments), `compute_verify_cell_kzg_proof_batch_challenge` hashes `RCKZGCBATCH__V1_`, sizes, unique commitments, then per cell (commitment index, cell index, cell, proof), `compute_weighted_sum_of_commitments` validates commitments only after deduplication, `compute_commitment_to_aggregated_interpolation_poly` aggregates cells by column, bit-reverses each used column, `fr_ifft`s it and shifts by `get_inv_coset_shift_for_cell`, `computed_weighted_sum_of_proofs` scales by `get_coset_shift_pow_for_cell` (`reverse_bits_limited` then index arithmetic into `roots_of_unity`), and the final pairing uses `g2_values_monomial[FIELD_ELEMENTS_PER_CELL]`. Show a batch that returns true with a cell that does not lie on the committed polynomial: the same `cell_index` supplied twice with different cells so their `r`-weighted sum interpolates while neither is valid; a commitment index or coset index that maps two columns to one shift; a cell with a non-canonical field element read after `r` was derived; a proof at infinity dropped by `g1_lincomb_fast`'s zero-point filter while its `r^i` weight still multiplies the commitment side. Identity: `*ok == true` if and only if for every i the cell at `cell_indices[i]` equals the coset evaluation of the polynomial committed by `commitments_bytes[i]` and `proofs_bytes[i]` opens it.",

    "High. RECOVERY MUST RETURN THE UNIQUE POLYNOMIAL THE SUPPLIED CELLS LIE ON, OR FAIL. `recover_cells_and_kzg_proofs` requires `CELLS_PER_BLOB <= num_cells <= CELLS_PER_EXT_BLOB` and strictly ascending indices below `CELLS_PER_EXT_BLOB`, writes each cell into `recovered_cells_fr` at `cell_indices[i] * FIELD_ELEMENTS_PER_CELL`, copies the input verbatim when `num_cells == CELLS_PER_EXT_BLOB`, otherwise `recover_cells` builds `missing_cell_indices` through `is_in_array`, asserts enough cells, computes the vanishing polynomial in `vanishing_polynomial_for_missing_cells`, multiplies, `fr_ifft`s, moves to a coset with `coset_fft`, divides by `fr_div` (unspecified on zero), and `coset_ifft`s back; proofs are then recomputed by `poly_lagrange_to_monomial` and `compute_fk20_cell_proofs`. Show a recovery whose output cells or proofs differ across nodes, or that emits cells and proofs for a polynomial the inputs do not lie on without an error: inputs that are consistent on the supplied indices but not of degree below `FIELD_ELEMENTS_PER_BLOB`; a coset point where `vanishing_poly_over_coset[i]` is zero; the full-input branch returning cells that are never checked against a degree bound while proofs are computed from them; an index set whose bit-reversed missing list has a duplicate. Identity: `recovered_cells` == the extension of the unique degree-below-4096 polynomial through the supplied cells, and `recovered_proofs[i]` == `compute_cells_and_kzg_proofs` proofs for that polynomial, or the call returns `C_KZG_BADARGS`.",

    "High. EVERY NODE MUST COMPUTE THE SAME BYTES FROM THE SAME BLOB. `blob_to_kzg_commitment` runs `blob_to_polynomial` then `g1_lincomb_fast` over `g1_values_lagrange_brp`; `compute_kzg_proof_impl` has an in-domain branch (`m != 0`) that zeroes `q_poly[m]` and rebuilds it from `z * (z - w_i)` denominators; `compute_blob_kzg_proof` derives `z` from `compute_challenge`; `compute_cells_and_kzg_proofs` calls `poly_lagrange_to_monomial`, asserts the top half is zero, `fr_fft`s to 8192 points, `bit_reversal_permutation`s cells and proofs, and `compute_fk20_cell_proofs` through `circulant_coeffs_stride`, `x_ext_fft_columns`, `wbits` tables and `g1_ifft_unscaled`. Show a blob for which two honest nodes emit different commitment, proof or cell bytes, or for which a proof this library emits fails this library's own verifier: a `z` equal to a root of the 8192 domain but not of the 4096 domain; a blob whose monomial form is not zero above 4096 so the `assert` aborts the process; a `precompute` of 0 versus 8 producing different `proofs`; an output serialised through `blst_p1_affine_compress` versus `bytes_from_g1` for the identity point. Identity: bytes returned by every compute function == the bytes the consensus-specs reference computes for the same blob, and `verify_*` of that output returns true.",

    "High. EVERY BYTE MUST BE VALIDATED BEFORE IT REACHES ARITHMETIC. `bytes_to_bls_field` rejects non-canonical scalars, `hash_to_bls_field` deliberately does not, `validate_kzg_g1` accepts infinity then requires `blst_p1_in_g1`, `blob_to_polynomial` validates 4096 elements in order, cells are validated element by element in `recover_cells_and_kzg_proofs` and `compute_commitment_to_aggregated_interpolation_poly` but only after `compute_verify_cell_kzg_proof_batch_challenge` hashed their raw bytes, and `commitments_equal` compares raw bytes, not points. Show untrusted bytes that reach `blst` unvalidated, or two byte strings that decode to one value yet are treated as different: a 48-byte string with the infinity bit set and non-zero payload that `blst_p1_uncompress` accepts; a compressed point with the sign bit set for the identity; a cell field element equal to the modulus; a commitment validated in `verify_kzg_proof` but never in `compute_blob_kzg_proof`'s challenge. Identity: every field element and group element used in an equation == the canonical decoding of the caller's bytes, and any non-canonical or off-curve input returns `C_KZG_BADARGS` before `*ok` can become true.",

    "High. EVERY INDEX AND LENGTH DERIVED FROM INPUT MUST STAY INSIDE ITS BUFFER. `num_cells` and `n` are `uint64_t` documented as trusted, yet `compute_verify_cell_kzg_proof_batch_challenge` computes `input_size` as sums of `num_cells * BYTES_PER_CELL`, `verify_cell_kzg_proof_batch` allocates `num_cells * sizeof(Bytes48)` for `unique_commitments`, `deduplicate_commitments` writes `indices_out[i]` for every i, `is_cell_used[cell_indices[i]]`, `commitment_weights[commitment_indices[i]]` and `aggregated_column_cells[column_index * FIELD_ELEMENTS_PER_CELL + fr_index]` index by attacker-supplied values, `bit_reversal_permutation` asserts on `n`, `get_inv_coset_shift_for_cell` asserts `cell_idx_rbl <= FIELD_ELEMENTS_PER_EXT_BLOB`, and `fr_batch_inv` mutates `out` before returning `C_KZG_BADARGS`. Show one input that writes or reads outside an allocation, wraps a size computation, or reaches an `assert` in a release build so the process aborts: a `num_cells` that overflows `input_size`; a cell index of `CELLS_PER_EXT_BLOB - 1` after `reverse_bits_limited`; an `n` such that `n * sizeof(blst_p1_affine)` wraps; a `c_kzg_calloc` of zero elements dereferenced later. Identity: every array access index < the length passed to the allocation that created it, and no input reachable from a blob or sidecar can terminate the process.",

    "High. THE BYTES A BINDING HANDS TO C MUST BE THE BYTES THE CLIENT PASSED, WITH THE COUNT IT PASSED. Java `ckzg_jni.c` trusts a `jlong count` cast to `size_t` and checks `GetArrayLength == count * BYTES_PER_*`; Node `kzg.cxx` derives `num_cells` from `Array::Length()` and `get_cell_index` from a JS number; Python `ckzg_wrap.c` derives counts from `PyBytes_Size` modulo element size; C# `Ckzg.cs` passes an `int count` and `ThrowOnInvalidLength(..., BytesPerCell * numCells)`; Go `main.go` casts slice lengths to `C.uint64_t` and unsafe-casts pointers; Rust `mod.rs` checks slice lengths then `as u64`; Zig `root.zig` returns null for empty slices; Nim and Elixir check equal lengths then call the ABI. Show a binding call where the count, the pointer or the output the client observes differs from what C validated: a negative or huge `count` that multiplies past `Integer.MAX_VALUE` yet matches a length check; a cell index above 2^53 or negative rounded by JS; an error return where the binding still reads an uninitialised `ok` or output buffer; a `verify_*` that maps `C_KZG_BADARGS` to `false` in one binding and to an exception in another so two clients disagree on the same sidecar. Identity: (pointer contents, count, ok/error) seen by the C function == (bytes, length, result) seen by the client, in every binding.",

    "High. THIS LIBRARY'S VERDICT MUST EQUAL THE REFERENCE SPECIFICATION'S VERDICT FOR EVERY INPUT. The consensus-specs treat an invalid input as a failed verification; here `verify_blob_kzg_proof_batch` accepts `n == 0`, `verify_cell_kzg_proof_batch` accepts `num_cells == 0`, `C_KZG_BADARGS` and `*ok == false` are distinct outcomes, `verify_cell_kzg_proof_batch` has no upper bound on `num_cells` while the spec bounds columns, `deduplicate_commitments` compares bytes where the spec compares points, and `compute_challenge` and both batch transcripts must match the spec byte for byte (domain, degree, counts, endianness, compressed encodings). Show an input that this library accepts and the reference rejects or the reverse, so that nodes running c-kzg fork from nodes running another implementation: a cell batch with a duplicate `(commitment, index)` pair; a proof at infinity for a zero blob; a `y` or `z` at the modulus boundary; a commitment whose two encodings dedupe differently; a transcript field ordered differently from the spec. Identity: `verify_*` here == `verify_*` in consensus-specs for the same bytes, and the (commitment, proof, cells) bytes computed here == the spec's.",

    "Critical. THE MISSING INVARIANT - what nobody built. No check ties `num_cells` or `n` back to the sizes of the buffers a binding actually allocated; nothing rejects duplicate `(commitment, cell_index)` pairs before their cells are summed; the challenge transcripts hash raw cell and commitment bytes before those bytes are validated, so validity and challenge derivation see different objects; `compute_kzg_proof`'s in-domain branch and `evaluate_polynomial_in_evaluation_form`'s shortcut are two code paths for one mathematical case; the point at infinity is accepted as a commitment and as a proof with no rule about what it commits to; and nothing asserts that a proof this library computes is accepted by this library's verifier. Identify the FIRST place one of these unstated soundness or determinism assumptions is violated by an unprivileged user publishing a blob transaction, blob sidecar or data-column sidecar, prove it with a C unit test in the style of src/test/tests.c or a binding test that asserts both sides (`ok` versus the pairing relation, bytes here versus the reference, index versus buffer length) before and after, and show that no later step in the client can detect or reverse it.",
]


scope_scan = [
]


def question_generator(target_file: str) -> str:
    """
    Generate KZG soundness / determinism / memory-safety audit questions for one c-kzg-4844 target.

    ```
    target_file format:
    "'File Name: src/eip4844/eip4844.c -> Scope: Critical. ...'"
    """

    prompt = f"""
    ```

    Generate cryptographic-library security audit questions for this exact c-kzg-4844
    target:

    {target_file}

    Project focus:
    c-kzg-4844 is the C implementation of the EIP-4844 and EIP-7594 Polynomial
    Commitments API that Ethereum execution and consensus clients link through the
    Go, Rust, Java, C#, Node.js, Python, Nim, Zig and Elixir bindings. Untrusted bytes
    - blobs, commitments, proofs, cells, cell indices, z and y values, and the counts
    that describe them - arrive from blob transactions, blob sidecars and data-column
    sidecars that any user can publish; honest nodes forward them into these functions
    unchanged. The library decides (a) whether `ok` equals the truth of the pairing
    relation for the supplied bytes; (b) whether every node computes the same
    commitment, proof, cell and verdict bytes as the reference specification; (c)
    whether every index and length derived from the input stays inside its buffer and
    no input can abort the process. A proof accepted that should fail, a verdict that
    differs between nodes, or a crash reachable from one sidecar is the bug.

    Rules:
    * Treat `File Name:` as the exact file.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Use exact C or binding symbols (function, static helper, macro, constant, struct
      field, return code) as they appear in the file.
    * EVERY question must close on an equality that must hold across a call. State it
      explicitly. Narrative questions with no stated equality are rejected.
    * Attacker is unprivileged only: an ordinary Ethereum user who submits a blob
      transaction, or publishes a blob sidecar or data-column sidecar, with their own
      keys and funds. They choose every byte of blobs, commitments, proofs, cells, cell
      indices, z, y and the number of items, and honest nodes pass those bytes into the
      public API through the bindings.
    * Attacker is NOT a node operator, a client developer misusing the API, the
      trusted-setup provider, or a malicious peer, node or RPC. No compromised
      dependency, build or device; no social engineering.
    * PROGRAM EXCLUSIONS - a question landing in any of these wastes the whole batch:
      - Tests, reference vectors, fuzz targets, generated bindings, trusted setup
        files, scripts, build and package files, READMEs and audits are OUT OF SCOPE.
      - Resource exhaustion, slow inputs, large allocations, timeouts, unbounded loops,
        cache growth and memory hygiene are OUT OF SCOPE. Memory corruption, reachable
        asserts and undefined behaviour from one input are IN scope.
      - The contents of the trusted setup are trusted; a wrong file is OUT OF SCOPE.
        Wrong tables derived from a correct file are IN scope.
      - Defects inside blst or inside a client with no path through this repo are OUT
        OF SCOPE; a weakness here that misuses blst or steers a client wrong is IN.
      - Also excluded: leaked keys, privileged accounts, centralization risk,
        best-practice notes, feature requests, publicly known issues, and findings
        with no path from a blob, sidecar or data-column sidecar.
    * IN-SCOPE IMPACTS - every question must land on one and name it:
      Critical: a forged proof, commitment or cell batch verifies, so invalid blob data
      is accepted and the chain can be split or unavailable data finalised; the same
      bytes verify on some nodes and fail on others.
      High: one blob or sidecar crashes or aborts every node running this library
      (memory corruption, reachable assert, UB); a valid proof rejected here but
      accepted by the reference, or the reverse, so more than a third of the network
      forks; a compute function emitting bytes that differ between honest nodes.
    * Every question must be a concrete real-world scenario an unprivileged party can
      trigger through the public API with bytes they publish on the network.
    * A returned `C_KZG_BADARGS` is a finding only when the reference accepts the same
      input, or when state was already mutated or memory already written - say which.
    * Generate 40 to 80 high-signal questions.
    * At least 70% must land on a Critical impact rather than a High one.
    * Every question must be testable locally with a C unit test in src/test/tests.c
      style or a binding test against the local trusted setup. Never propose testing
      on mainnet or a public testnet.
    * Avoid generic checklist questions and repeated root causes.
    * Prefer questions that name TWO values that must be equal and ask whether they are:
      ok and the pairing relation, batch verdict and per-item verdicts, bytes here and
      bytes in the reference, index and buffer length, count passed and count checked.

    Known dead ends - do NOT generate questions about these:
    * Anything needing a node operator, client developer, trusted-setup provider, peer
      or RPC to act maliciously.
    * A bug inside blst or a client with no path through this repo.
    * Slow verification, big allocations, unbounded memory, logging, or an input that
      only harms the attacker's own transaction.
    * Findings only reproducible through tests, fuzzers or tooling.

    Core equalities (each question must close on one):
    * SOUNDNESS: `*ok == true` iff the pairing relation holds for the decoded inputs.
    * BATCH TRUTH: batch verdict == AND of the per-item verdicts, for every n.
    * REFERENCE TRUTH: bytes and verdicts here == consensus-specs for the same input.
    * VALIDATION TRUTH: every value in an equation == canonical decoding of input bytes.
    * BOUNDS TRUTH: every index < buffer length; no input aborts the process.
    * BINDING TRUTH: (bytes, count, result) seen by C == (bytes, length, result) seen
      by the client.

    Each question must include:
    1. target function, static helper or constant;
    2. attacker input (the concrete blob, commitment, proof, cell, index, count or
       field-element bytes that matter);
    3. preconditions (which API, which binding, n or num_cells, precompute, in-domain
       point, infinity point, duplicate entries);
    4. call sequence through the binding, the public function and its helpers;
    5. the equality that breaks, written explicitly;
    6. scoped impact and which nodes are affected;
    7. proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Method: function_name] Can an unprivileged ATTACKER_INPUT under PRECONDITIONS trigger CALL_SEQUENCE, breaking the equality EQUALITY, causing scoped impact: SCOPE_IMPACT against PARTY? Proof idea: C unit test PARAMETERS asserting SOUNDNESS, BATCH_TRUTH, REFERENCE_TRUTH, VALIDATION_TRUTH, BOUNDS_TRUTH, or BINDING_TRUTH.",
    ]
    """
    return prompt


def audit_format(security_question: str) -> str:
    """
    Generate a KZG soundness / determinism / memory-safety exploit-validation prompt for c-kzg-4844.
    """

    prompt = f"""# SECURITY AUDIT PROMPT

## Question
{security_question}

## Rules
- Use existing repo context only. Analyze only this question and scoped impact.
- Attacker is unprivileged only: an ordinary Ethereum user who submits a blob transaction or publishes a blob sidecar or data-column sidecar. They choose every byte of blobs, commitments, proofs, cells, cell indices, z, y and item counts; honest nodes pass those bytes into the public API through the bindings.
- Reject anything requiring a node operator, a client developer misusing the API, the trusted-setup provider, a malicious peer/node/RPC, a compromised dependency, build or device, or social engineering.
- OUT OF SCOPE, reject on sight: tests, reference vectors, fuzz targets, generated bindings, trusted setup files, scripts, build and package files, READMEs, audits; resource exhaustion, slow inputs, large allocations, timeouts, unbounded loops, cache growth and memory hygiene; a wrong trusted setup file; defects inside blst or a client with no path through this repo; publicly known issues; best-practice notes; theoretical findings.
- The impact must be one of: Critical - a forged proof, commitment or cell batch verifies so invalid blob data is accepted or the chain splits, or the same bytes verify on some nodes and fail on others; High - one blob or sidecar crashes or aborts every node running this library (memory corruption, reachable assert, UB), a verdict that differs from the reference specification so more than a third of the network forks, or a compute function emitting bytes that differ between honest nodes.
- Focus on real impact: a proof accepted that should fail, a verdict that differs between nodes, or a crash reachable from one sidecar.

## Validate
- Write the equality the question claims is broken between two named values BEFORE tracing any code.
- Trace the exact reachable path from the attacker's bytes and record every read and write of `n` / `num_cells`, `cell_indices`, `commitment_indices`, the decoded `fr_t` and `g1_t` values, the challenge transcript bytes, `r_powers`, every array index, and `*ok`.
- Evaluate both sides of the equality before and after. If they still match, output no vulnerability.
- Check whether `bytes_to_bls_field`, `validate_kzg_g1`, the `cell_indices` bound checks, `deduplicate_commitments`, the `n == 0` / `n == 1` short-circuits, the `assert` calls, the binding length checks, or blst's own subgroup and curve checks already prevent the divergence.
- State what the attacker gains per input and whether it is repeatable.
- Require exact file/function support and a reproducible C unit test or binding test against the local trusted setup.

## Output
If valid, output exactly:

### Title
[Bug statement] - ([File: file_path])

### Summary
[2-3 sentences]

### Finding Description
[The broken equality, the code path, root cause, the attacker's exact bytes, exploit flow, and why existing guards fail]

### Impact Explanation
[What verifies, diverges or crashes, which nodes, repeatability, matching severity category]

### Likelihood Explanation
[Preconditions, API and binding required, attacker cost, feasibility, repeatability]

### Recommendation
[Specific fix]

### Proof of Concept
[C unit test or binding test plan with the exact assertions on both sides of the equality]

If invalid, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict bounty-style validation prompt for c-kzg-4844 claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and Researcher.Md for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- A claim is only valid if the report states the broken equality between two named values and shows both sides concretely. Reject prose-only claims.
- Reject anything requiring a node operator, a client developer misusing the API, the trusted-setup provider, a malicious peer/node/RPC, a compromised dependency, build or device, or social engineering.
- OUT OF SCOPE, reject on sight: tests, reference vectors, fuzz targets, generated bindings, trusted setup files, scripts, build and package files, READMEs, audits; resource exhaustion, slow inputs, large allocations, timeouts, unbounded loops, cache growth and memory hygiene; a wrong trusted setup file; defects inside blst or a client with no path through this repo; publicly known issues; centralization risk; best-practice notes; feature requests; theoretical findings.
- The impact must be one of: Critical - a forged proof, commitment or cell batch verifies so invalid blob data is accepted or the chain splits, or the same bytes verify on some nodes and fail on others; High - one blob or sidecar crashes or aborts every node running this library (memory corruption, reachable assert, UB), a verdict that differs from the reference specification so more than a third of the network forks, or a compute function emitting bytes that differ between honest nodes.
- Reject claims where the only effect is on the attacker's own transaction or the attacker's own node.
- Reject if the bug was already fixed, publicly disclosed, or covered by a known-issues list.
- A valid report must be triggerable by an unprivileged party against the current code through bytes they can publish on the network.
- A PoC is mandatory. Prefer #NoVulnerability over speculative reports.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function/helper/constant, and line references.
2. The equality written explicitly, with both sides shown before and after.
3. Clear root cause: which decoding gap, transcript or challenge drift, index or length error, batch aggregation flaw, or spec divergence causes it.
4. Reachable exploit path: preconditions -> attacker bytes -> binding, public function and helper sequence -> observed divergence.
5. `bytes_to_bls_field`, `validate_kzg_g1`, the `cell_indices` bound checks, `deduplicate_commitments`, the `n == 0` / `n == 1` short-circuits, the `assert` calls, the binding length checks and blst's own checks reviewed and shown insufficient.
6. Impact stated concretely: what verifies, diverges or crashes, on which nodes, and whether it is repeatable.
7. Reproducible proof: C unit test or binding test against the local trusted setup, with the asserted values.

## Silent Triage Questions
Before output, internally answer:
- What exactly is the equality, and does it actually fail?
- Can an ordinary user publishing a blob, sidecar or data-column sidecar trigger it with no privileged role?
- Is the flaw in this repo's code, not in blst, a client or the trusted setup file?
- What verifies, diverges or crashes, on which nodes, and can it be repeated?
- Would the Ethereum Foundation bug bounty panel accept the exploit path for c-kzg-4844?
- What exact test would prove it?

## Output
If valid, output exactly:

Audit Report

## Title
[Clear vulnerability statement] - ([File: file_path])

## Summary
[2-3 sentence summary of the broken equality and impact]

## Finding Description
[Exact code path, the equality, root cause, exploit flow, and why existing guards fail]

## Impact Explanation
[What verifies, diverges or crashes, affected nodes, repeatability, severity category]

## Likelihood Explanation
[Attacker capability, preconditions, state required, cost, feasibility]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or C unit test / binding test plan with concrete assertions]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for c-kzg-4844.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Rules
- Use in-scope repo context only (`src/common/**`, `src/eip4844/**`, `src/eip7594/**`, `src/setup/**`, `src/ckzg.c` and the non-test, non-generated binding sources under `bindings/*`). Do not ask for code or claim missing files.
- Use the external report only as a bug-class hint, not as proof.
- Keep only unprivileged analogs that break an equality: `ok` true while the pairing relation is false, a batch verdict that is not the AND of its items, bytes or verdicts that differ from the reference specification, a value used in an equation that is not the canonical decoding of the input, an index outside its buffer or an input that aborts the process, or a count or result that differs between a binding and the C function.
- OUT OF SCOPE, reject on sight: tests, reference vectors, fuzz targets, generated bindings, trusted setup files, scripts, build files, READMEs; resource exhaustion, slow inputs, large allocations, timeouts, unbounded loops, cache growth and memory hygiene; a wrong trusted setup file; defects inside blst or a client with no path here; anything requiring a node operator, client developer, trusted-setup provider, peer or RPC to act maliciously; publicly known issues; best-practice notes; theoretical findings.
- The impact must be one of: Critical - a forged proof, commitment or cell batch verifies so invalid blob data is accepted or the chain splits, or the same bytes verify on some nodes and fail on others; High - one blob or sidecar crashes or aborts every node running this library, a verdict that differs from the reference specification so more than a third of the network forks, or a compute function emitting bytes that differ between honest nodes.
- Reject analogs where the only effect is on the attacker's own transaction or node.

## Validate
- Map the bug class to the strongest reachable path in this repo and state the equality it would break.
- Evaluate both sides before and after the attacker's bytes.
- Prove root cause with exact file/function support.
- Accept only concrete forged acceptance, cross-node divergence, spec divergence, memory corruption, reachable abort, or binding/C mismatch.

## Output (Strict)
If valid analog exists, output:

### Title
[Clear vulnerability statement] - ([File: file_path])

### Summary
### Finding Description
### Impact Explanation
### Likelihood Explanation
### Recommendation
### Proof of Concept

If not, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt
