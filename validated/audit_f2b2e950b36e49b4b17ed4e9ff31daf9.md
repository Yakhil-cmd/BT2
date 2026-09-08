[1](#0-0)

### Citations

**File:** src/eip7594/eip7594.c (L1-30)
```c
/*
 * Copyright 2024 Benjamin Edgington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "eip7594/eip7594.h"
#include "common/alloc.h"
#include "common/ec.h"
#include "common/fr.h"
#include "common/lincomb.h"
#include "common/utils.h"
#include "eip7594/fft.h"
#include "eip7594/fk20.h"
#include "eip7594/poly.h"
#include "eip7594/recovery.h"

#include <assert.h> /* For assert */
#include <string.h> /* For memcpy & strlen */

```
