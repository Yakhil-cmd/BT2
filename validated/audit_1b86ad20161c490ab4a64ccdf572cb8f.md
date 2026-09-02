Based on my research, I've identified a valid analog vulnerability that matches the bug class from the report (a check/scoping mechanism that fails to account for an existing binding, letting the actual operation exceed what was authorized).

### Title
API token stack-scoping bypass in CCMenu endpoint allows cross-stack read - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` supports being scoped to a single stack via its `stack_id` column, and `Shipit::Api::BaseController` enforces this scope for every API endpoint by intersecting the requested stack with the client's authorized stack set. `Shipit::Api::CCMenuController` overrides the `stack` resolution method and, in doing so, drops this scoping check entirely, allowing any authenticated `read:stack` token — even one bound to a single stack — to read the CCMenu status of an arbitrary stack.

### Finding Description
`Shipit::Api::BaseController` establishes the token-to-stack authorization binding: a client's accessible stacks are `Stack.where(id: current_api_client.stack_id)` when the client is scoped, or `Stack.all` otherwise, and the resolved `stack` is looked up from that scoped set: [1](#0-0) 

Every other API controller (`Stacks`, `Deploys`, `Tasks`, `Hooks`) relies on this `stacks`/`stack` helper, so a token whose `ApiClient#stack_id` is set to stack A can never resolve or act on stack B.

`Shipit::Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely, resolving directly against the full `Stack` table using only the client-supplied `params[:stack_id]`: [2](#0-1) 

It still declares `require_permission :read, :stack`, which only checks that the token's `permissions` array includes `"read:stack"` — it says nothing about *which* stack: [3](#0-2) 

Because `ApiClient.authenticate` only verifies the signed client id and does not re-derive or re-check `stack_id` at the controller boundary here, the binding "stack a token authorizes" (`ApiClient#stack_id`) is decoupled from "stack a token touches" (`params[:stack_id]` resolved in `CCMenuController#stack`).

### Impact Explanation
Any holder of a `read:stack`-permissioned `ApiClient` token — including a token deliberately scoped by an operator to a single, possibly less-sensitive stack — can enumerate `stack_id`/`to_param` values and read the build/deploy status (`lastBuildStatus`, `lastBuildLabel`, lock state, etc.) of any stack in the Shipit installation via `GET /api/:stack_id/ccmenu.xml?token=...`. This is an unauthenticated-for-that-resource read of stack state, matching the "High" impact category (unauthenticated read of stack state) since the token was never granted access to that specific stack.

### Likelihood Explanation
This does not require any privileged action beyond possessing a legitimately-issued, narrowly-scoped `read:stack` token (e.g., one created by `CCMenuUrlController` or via the `ApiClients` UI and intentionally bound to one stack). No signature forgery, no repository write access, and no session compromise are needed — only knowledge or enumeration of another stack's `to_param`/id, which is not treated as a secret elsewhere in the app (stack slugs are visible in URLs).

### Recommendation
Have `Api::CCMenuController#stack` resolve through the same scoped `stacks` collection used by `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` unconditionally, so the `ApiClient#stack_id` binding established at authentication time is honored for every read, exactly as it is for the other API controllers.

### Proof of Concept
1. An operator creates (or the app auto-creates via `CCMenuUrlController#client`) an `ApiClient` with `permissions: ["read:stack"]` intended to be scoped to `stack_id: A` (Stack A).
2. Obtain that client's `authentication_token` (e.g., from the generated CCMenu URL for Stack A).
3. Request `GET /api/<stack-B-param>/ccmenu.xml?token=<token-for-stack-A>` where Stack B is a different, unrelated stack.
4. `CCMenuController#authenticate_api_client` succeeds (token is valid), `require_permission :read, :stack` passes (permission array contains `read:stack`), and `stack` resolves Stack B directly via `Stack.from_param!`, bypassing the `stack_id` scope check performed everywhere else — the response discloses Stack B's build/deploy status even though the token was authorized only for Stack A.

**Note on verification limits:** I was unable to retrieve the full contents of `app/controllers/shipit/api_clients_controller.rb` in this session to confirm every code path by which an `ApiClient#stack_id` can be assigned via the web UI (tool calls failed on the final iteration). The core authorization bypass — `CCMenuController#stack` bypassing the `stacks` scoping enforced in `BaseController` — is confirmed directly from the retrieved source, and the `stack_id` scoping mechanism itself is confirmed live in `base_controller.rb`. A Devin session with full file access should confirm the exact UI/flow for assigning `stack_id` to corroborate real-world exploitability before remediation.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-36)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** app/models/shipit/api_client.rb (L38-45)
```ruby
    def check_permissions!(operation, scope)
      required_permission = "#{operation}:#{scope}"
      unless permissions.include?(required_permission)
        raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
      end

      true
    end
```
