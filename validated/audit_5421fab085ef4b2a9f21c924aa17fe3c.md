[1](#0-0)

### Citations

**File:** src/eip4844/eip4844.c (L17-48)
```c
#include "eip4844/eip4844.h"
#include "common/alloc.h"
#include "common/ec.h"
#include "common/fr.h"
#include "common/lincomb.h"
#include "common/ret.h"
#include "common/utils.h"
#include "setup/settings.h"

#include <assert.h> /* For assert */
#include <stdlib.h> /* For NULL */
#include <string.h> /* For memcpy & strlen */

////////////////////////////////////////////////////////////////////////////////////////////////////
// Macros
////////////////////////////////////////////////////////////////////////////////////////////////////

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
