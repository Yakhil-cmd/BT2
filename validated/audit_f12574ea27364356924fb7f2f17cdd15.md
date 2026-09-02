### Title
CCMenu API endpoint bypasses ApiClient stack scoping, allowing a stack-scoped token to read any stack's status - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup helper to bypass the stack-scoping enforced by `Shipit::Api::BaseController`, breaking the equality "stack a token authorizes == stack the request touches." A token minted with `stack_id` set to stack A can be used to read CI/deploy status for any other stack B by supplying B's id in the URL.

### Finding Description
`Shipit::Api::BaseController` defines the intended trust boundary between an `ApiClient` token and the stacks it may act on: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` record has a `stack_id` set (i.e., a stack-scoped token, as used in fixtures/tests like `here_come_the_walrus`, which is scoped to `shipit` and is shown in tests to see only its own stack: [2](#0-1) ).

`CCMenuController`, however, defines its own private `stack` method that goes straight to the unscoped `Stack.from_param!(params[:stack_id])`, never touching `stacks`: [3](#0-2) 

It also overrides `authenticate_api_client` to accept the token from `params[:token]` (URL-embedded, as is standard for CI status badge/monitor endpoints like CCTray/CCMenu) rather than the `Authorization` header used elsewhere: [4](#0-3) 

`require_permission :read, :stack` only checks that the client's `permissions` array includes `read:stack`; it performs no per-record scoping — that check is only enforced by the (bypassed) `stacks` helper: [5](#0-4) 

So the binding that should hold — `current_api_client.stack_id == stack.id` (or "no constraint if unscoped") — is broken specifically in this controller: the token's authorized stack (fixed at token-creation time via the `ApiClient.stack_id` column) is decoupled from the stack whose data is actually rendered (attacker-supplied `params[:stack_id]` in the request path, per the route `get '/stacks/*stack_id' => 'ccmenu#show'`).

### Impact Explanation
Any holder of a stack-scoped `read:stack` API token (e.g., a CI status-badge token meant only for one stack/environment) can pass a different stack's id/environment triple in the URL and receive that other stack's deploy/rollback status (id, running state, end time) via `stack.deploys_and_rollbacks.last`. This is an unauthorized cross-stack read of stack/deploy state that the `ApiClient.stack_id` scoping was specifically designed to prevent, matching the High-severity class "escalation into … unauthenticated/unauthorized read of stack state, task streams or deploy output." It does not require repository write access, a GitHub App key, or session cookies — only possession of any valid, even narrowly-scoped, API token with `read:stack` permission and knowledge/guessing of another stack's `owner/repo/environment` path (which is often predictable or discoverable, e.g., via the public stacks listing UI).

### Likelihood Explanation
High for any deployment that issues scoped API tokens for CCMenu/CI status widgets (a documented, intended use case) to less-trusted consumers than the full `read:stack` global capability. No special conditions are required beyond having one valid scoped token — the flaw is a straightforward code path bypass, not a race condition or timing issue.

### Recommendation
Change `CCMenuController#stack` to reuse the scoped `stacks` collection from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so the `current_api_client.stack_id` restriction is enforced consistently across all API controllers, including CCMenu.

### Proof of Concept
1. Create two stacks, `owner/repoA/production` (id A) and `owner/repoB/production` (id B).
2. Create an `ApiClient` scoped to stack A only (`stack_id: A`) with permission `read:stack` — this is the intended "least privilege" CI badge token.
3. Request `GET /api/stacks/owner/repoB/production/ccmenu?token=<tokenA>`.
4. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` unconditionally instead of `stacks.from_param!`, the request succeeds and returns stack B's latest deploy/rollback status, even though the token is scoped to stack A only — contrary to the behavior enforced (and unit-tested) for every other API controller (`test/controllers/api/stacks_controller_test.rb:217-223`).

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

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
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
