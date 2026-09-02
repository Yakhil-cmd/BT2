### Title
Stack-scoped `ApiClient` token can read the deploy status of any stack via `CCMenuController#stack` bypassing the stack scoping check - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides `#stack` to look up `Stack.from_param!(params[:stack_id])` directly instead of using the scoped `stacks` helper defined in `BaseController`. This breaks the binding "the stack(s) an `ApiClient` token is authorized for == the stack the controller action operates on," letting a token scoped to a single stack read the CI/deploy status of any stack in the installation.

### Finding Description
`Shipit::Api::BaseController` defines a scoping mechanism intended to restrict a stack-scoped `ApiClient` to only the stack it was created for: [1](#0-0) 

`current_api_client.stack_id?` is true when the `ApiClient` was created with a specific `stack:` association (see fixture `here_come_the_walrus`, scoped to stack `shipit`), and in that case `stacks` (and therefore `stack`) is restricted to `Stack.where(id: current_api_client.stack_id)`. `Shipit::Api::StacksController` and other API controllers rely on this shared `stack`/`stacks` helper, correctly enforcing the scope, as shown by the test `"an api client scoped to a stack will only see that one stack"` and `"#index returns a list of stacks filtered by repo and api client"`.

However, `CCMenuController` redefines both `authenticate_api_client` (to also allow a `?token=` query param, appropriate for CCMenu/CI-status clients) and `stack`, and its override of `stack` does not reuse the scoped `stacks` collection: [2](#0-1) 

Because `Stack.from_param!` queries the entire `Stack` table with no scoping by `current_api_client`, an `ApiClient` created with `stack: <some stack>` (limited visibility) can still authenticate on the CCMenu endpoint with its token and pass an arbitrary `stack_id` to read another, unrelated stack's latest deploy/rollback status and name, even though `require_permission :read, :stack` only checks that the client has the generic `read:stack` permission bit — it never re-validates that the target stack is the one the client is bound to.

This is a concrete instance of the "stack a token authorizes vs. stack it touches" binding break described in the report's bug class (parallel to the original Solidity finding: a check that exists in one code path — `stacks.from_param!` — is silently missing in a sibling code path — `Stack.from_param!` — that handles equivalent input).

### Impact Explanation
This allows unauthorized, cross-stack read access to stack build/deploy state (last deploy id, status, timestamp) using a token that was only meant to authorize a single stack. Per the engine's severity classification, this matches the High-impact category: "unauthenticated read of stack state, task streams or deploy output" achieved via an authorization scope escalation rather than proper session/API-client authentication. It does not require repository write access, `webhook_secret`, or any privileged credential beyond a normal, narrowly-scoped `ApiClient` token that many installations hand out to individual teams/services expecting per-stack isolation.

### Likelihood Explanation
Likelihood is high for any Shipit installation that issues stack-scoped `ApiClient` tokens (a documented, intended use of the `stack` association on `ApiClient`) and exposes the CCMenu endpoint (`api/ccmenu#show`), which is a standard, documented CI-status integration endpoint. Exploitation only requires knowledge/guessing of another stack's `to_param` (`owner/repo/environment`), which is often predictable or discoverable.

### Recommendation
Change `CCMenuController#stack` to reuse the inherited, scoped `stacks` collection instead of querying `Stack` unscoped:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This ensures that a stack-scoped `ApiClient` token can never resolve a stack outside `current_api_client.stack_id`, restoring the same invariant enforced by `BaseController`.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack: repo-a/production` with `permissions: ['read:stack']` (e.g., fixture `here_come_the_walrus`).
2. Obtain its `authentication_token`.
3. Send `GET /api/ccmenu/repo-b/staging?token=<token>` (any other stack's `to_param`, e.g. `repo-b/staging`), where `repo-b/staging` is a stack the client was never granted access to.
4. `authenticate_api_client` succeeds via `ApiClient.authenticate(params[:token])`; `require_permission :read, :stack` passes because the client does have the generic `read:stack` permission.
5. `stack` resolves via `Stack.from_param!(params[:stack_id])` (unscoped), returning `repo-b/staging`, and its latest deploy/rollback XML status is rendered — disclosing information about a stack the token was never authorized to see.

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
