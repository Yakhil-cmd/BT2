### Title
CCMenuController#stack bypasses stack_id scoping, allowing cross-tenant read of stack/deploy status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController#stack` resolves through the scoped `#stacks` method, which filters by `current_api_client.stack_id` when set, and `stacks.from_param!` raises `ActiveRecord::RecordNotFound` for any stack outside that scope. `Api::CCMenuController` overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` relation, so a stack-scoped API client (or token) can read the CCMenu status/latest deploy XML for any stack in the system, not just the one it's scoped to.

### Finding Description
Binding: for every subclass of `BaseController`, `stack` must equal `stacks.from_param!(params[:stack_id])` where `stacks == current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [1](#0-0) .

`Api::CCMenuController` overrides `#stack` to bypass this scoping entirely: [2](#0-1) 
It calls `Stack.from_param!` on the unscoped class, not `stacks.from_param!`. Since `#authenticate_api_client` in this controller is also overridden to authenticate via `params[:token]` (a valid stack-scoped `ApiClient` token) [3](#0-2) , an attacker holding any valid API token scoped to stack A can request `show` with `stack_id` pointing to stack B, and the controller will resolve and render stack B's status (via `deploys_and_rollbacks.last`) without any `stack_id` equality check against `current_api_client.stack_id`.

`require_permission :read, :stack` only calls `current_api_client.check_permissions!(:read, :stack)` [4](#0-3)  — this checks operation/scope permission, not which specific stack ID the token is limited to. There is no separate re-check that the resolved `stack.id` matches `current_api_client.stack_id`; that check only happens implicitly via the `stacks` scoping in the base `#stack`, which CCMenuController does not use.

### Impact Explanation
This exposes stack/build/deploy status (branch, environment, latest deploy id, end time, running state) for stacks the calling API token is not authorized to see. This is an unauthenticated-in-effect (any valid token, regardless of assigned stack) cross-tenant information disclosure — matching "unauthorized read of stack state" in the High severity category. It's repeatable against any stack ID in the target Shipit instance by any party holding one valid API token (which per the rules here would require some token; however, the audit under strict "unprivileged only" attacker model — no ApiClient token — this specific vector requires possessing *a* token, even if scoped to an unrelated stack).

### Likelihood Explanation
Precondition: attacker must already possess a valid `ApiClient` API token (any stack-scoped token qualifies) — this is not the fully anonymous/unauthenticated attacker described in the audit's strict threat model (who holds "no ApiClient token"). Given the rules explicitly state the attacker "hold[s] no ... ApiClient token," this specific bypass requires a precondition the defined attacker model excludes. If a token is presumed available (e.g., a multi-tenant Shipit deployment issuing per-repo API tokens to less-trusted integrators), exploitation is trivial and repeatable via a single GET request with an arbitrary `stack_id`.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` method, consistent with the base class:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

### Proof of Concept
Minitest plan (`test/controllers/api/ccmenu_controller_test.rb`):
1. Create `stack_a` and `stack_b`.
2. Create an `ApiClient` scoped to `stack_a.id` with `:read`/`:stack` permission.
3. `OutputsControllerTest`: request with that client's credentials and `stack_id = stack_b.to_param` → assert `response.status == :not_found` (proves `stacks.from_param!` enforces scope).
4. `CCMenuControllerTest`: request `GET /1.0/stacks/:stack_b_id.xml?token=<stack_a-scoped-token>` → currently asserts `response.status == :ok` and body contains `stack_b`'s data, demonstrating the scope bypass. Fixing per the recommendation should flip this assertion to `:not_found`.

Given the attacker-model caveat above (requires possession of a valid token, which the defined "unprivileged" attacker does not have), this finding is valid as a real code defect but falls outside the strict zero-credential attacker model specified in the rules.

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```
