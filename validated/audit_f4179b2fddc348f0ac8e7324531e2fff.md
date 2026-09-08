[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** bindings/node.js/src/kzg.cxx (L169-178)
```text
inline uint64_t get_cell_index(const Napi::Env &env, const Napi::Value &val) {
    if (!val.IsNumber()) {
        Napi::TypeError::New(env, "cell index should be a number")
            .ThrowAsJavaScriptException();
        /* TODO: how will the caller know there was an error? */
        return 0;
    }
    double number = val.As<Napi::Number>().DoubleValue();
    return static_cast<uint64_t>(number);
}
```

**File:** bindings/node.js/src/kzg.cxx (L850-963)
```text
Napi::Value VerifyCellKzgProofBatch(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    Napi::Value result = env.Null();
    if (!(info[0].IsArray() && info[1].IsArray() && info[2].IsArray() &&
          info[3].IsArray())) {
        Napi::Error::New(
            env, "commitments, cell_indices, cells, and proofs must be arrays"
        )
            .ThrowAsJavaScriptException();
        return result;
    }
    Napi::Array commitments_param = info[0].As<Napi::Array>();
    Napi::Array cell_indices_param = info[1].As<Napi::Array>();
    Napi::Array cells_param = info[2].As<Napi::Array>();
    Napi::Array proofs_param = info[3].As<Napi::Array>();
    KZGSettings *kzg_settings = get_kzg_settings(env, info);
    if (kzg_settings == nullptr) {
        return env.Null();
    }

    C_KZG_RET ret;
    bool out;
    Bytes48 *commitments = NULL;
    uint64_t *cell_indices = NULL;
    Cell *cells = NULL;
    Bytes48 *proofs = NULL;

    uint64_t num_cells = cells_param.Length();

    if (commitments_param.Length() != num_cells ||
        cell_indices_param.Length() != num_cells ||
        proofs_param.Length() != num_cells) {
        Napi::Error::New(
            env,
            "Must have equal lengths for commitments, cell_indices, cells, "
            "and proofs"
        )
            .ThrowAsJavaScriptException();
        goto out;
    }

    commitments = (Bytes48 *)calloc(
        commitments_param.Length(), sizeof(Bytes48)
    );
    if (commitments == nullptr) {
        Napi::Error::New(env, "Error while allocating memory for commitments")
            .ThrowAsJavaScriptException();
        goto out;
    }
    cell_indices = (uint64_t *)calloc(
        cell_indices_param.Length(), sizeof(uint64_t)
    );
    if (cell_indices == nullptr) {
        Napi::Error::New(env, "Error while allocating memory for cell_indices")
            .ThrowAsJavaScriptException();
        goto out;
    }
    cells = (Cell *)calloc(cells_param.Length(), sizeof(Cell));
    if (cells == nullptr) {
        Napi::Error::New(env, "Error while allocating memory for cells")
            .ThrowAsJavaScriptException();
        goto out;
    }
    proofs = (Bytes48 *)calloc(proofs_param.Length(), sizeof(Bytes48));
    if (proofs == nullptr) {
        Napi::Error::New(env, "Error while allocating memory for proofs")
            .ThrowAsJavaScriptException();
        goto out;
    }

    for (uint64_t i = 0; i < num_cells; i++) {
        // add HandleScope here to release reference to temp values
        // after each iteration since data is being memcpy
        Napi::HandleScope scope{env};
        Bytes48 *commitment = get_bytes48(
            env, commitments_param[i], "commitmentBytes"
        );
        if (commitment == nullptr) {
            goto out;
        }
        memcpy(&commitments[i], commitment, BYTES_PER_COMMITMENT);
        cell_indices[i] = get_cell_index(env, cell_indices_param[i]);
        Cell *cell = get_cell(env, cells_param[i]);
        if (cell == nullptr) {
            goto out;
        }
        memcpy(&cells[i], cell, BYTES_PER_CELL);
        Bytes48 *proof = get_bytes48(env, proofs_param[i], "proofBytes");
        if (proof == nullptr) {
            goto out;
        }
        memcpy(&proofs[i], proof, BYTES_PER_PROOF);
    }

    ret = verify_cell_kzg_proof_batch(
        &out, commitments, cell_indices, cells, proofs, num_cells, kzg_settings
    );
    if (ret != C_KZG_OK) {
        std::ostringstream msg;
        msg << "Error in verifyCellKzgProofBatch: " << from_c_kzg_ret(ret);
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        goto out;
    }

    result = Napi::Boolean::New(env, out);

out:
    free(commitments);
    free(cell_indices);
    free(cells);
    free(proofs);

    return result;
}
```
