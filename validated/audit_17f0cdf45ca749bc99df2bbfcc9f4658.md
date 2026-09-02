## Analysis

The external report's root cause is a **check‑then‑use gap**: `BlackGovernor` verifies voting eligibility at one point (NFT ownership at proposal creation/vote-start) but the actual vote-casting act is validated against a different, mutable state (current NFT owner), letting the same underlying voting weight be exercised twice under two different addresses.

The equivalent binding in this engine is: **the stack an `ApiClient` token is scoped to** (`ApiClient#stack_id`) **must equal the stack whose data the token is used to read**. `Shipit::Api::BaseController` enforces this via its `stacks`/`stack` helpers, but `Shipit::Api::CCMenuController` re-implements `stack` in a way that breaks the equality.Both files were already retrieved earlier via `codebase_search`. I have enough to finalize.

### Title
Stack-scoped API tokens bypass their stack authorization in `CCMenuController` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`ApiClient` records can be scoped to a single `Stack` (`stack_id`), and `Shipit::Api::BaseController` is designed to restrict every scoped client to that one stack via its `stacks`/`stack` helpers. `Shipit::Api::CCMenuController`, however, overrides `stack` to look the stack up globally (`Stack.from_param!(params[:stack_id])`) instead of going through the scoped `stacks` collection, and its permission check only verifies that the client has the `read:stack` permission string — not that the requested stack matches the client's `stack_id`. This lets a token that was only ever authorized for one stack read CI/build state for **any** stack in the installation.

### Finding Description
`Shipit::Api::BaseController` implements the intended scoping: [1](#0-0) 

`stacks` restricts the visible set to `current_api_client.stack_id` when the client is scoped, and `stack` (used by `StacksController`, `CommitsController`, etc.) is derived from that restricted collection — so a scoped client can never resolve a `Stack` it wasn't granted.

`require_permission!` only checks that the permission string is present in the client's `permissions` array; it performs no per-object/stack comparison: [2](#0-1) 

`CCMenuController` requires only `read:stack` and, critically, redefines `stack` to bypass the scoped `stacks` helper entirely, resolving directly against the global `Stack` model using the client-supplied `params[:stack_id]`: [3](#0-2) 

Test fixtures confirm stack-scoped clients exist by design (e.g. `here_come_the_walrus`, scoped to the `shipit` stack with only `read:stack`): [4](#0-3) 

And `StacksController` tests confirm the *intended* effect of scoping — a scoped client only sees its own stack when going through the properly-scoped path: [5](#0-4) 

**Binding that should hold:** `current_api_client.stack_id == stack.id` for every stack-scoped read. **Before the request:** the token is minted/authorized for exactly one stack (`stack_id` set on the `ApiClient` row). **After the request to `CCMenuController#show` with a foreign `stack_id` param:** the controller returns CI/build state (`lastBuildStatus`, `lastBuildLabel`, lock status, etc.) for a stack the token was never scoped to, because `stack` resolves via unscoped `Stack.from_param!` rather than the scoped `stacks` collection, and `check_permissions!` never inspects which stack is being accessed.

### Impact Explanation
This breaks the "stack a token authorises versus a stack it touches" binding described in the scope rules. Any holder of a legitimately-issued, narrowly-scoped `read:stack` `ApiClient` token (e.g. a CCMenu integration token meant for a single project) can enumerate build/lock status for every other stack in the Shipit instance simply by varying the `stack_id` request parameter — an unauthenticated (from the perspective of that specific stack) read of stack state, matching the High-severity impact category ("unauthenticated read of stack state ... deploy output").

### Likelihood Explanation
High. The attacker only needs one legitimately obtained, stack-scoped `read:stack` token (these are routinely handed out for CI dashboard integrations, per `CCMenuUrlController`) and the numeric/slug identifier of another stack, which is not secret (stack names/environments are visible in the UI/URLs). No privileged access, signature forgery, or additional credentials are required beyond the token itself.

### Recommendation
In `Shipit::Api::CCMenuController`, resolve `stack` through the scoped `stacks` helper (or explicitly verify `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id`) instead of calling `Stack.from_param!` directly against the unscoped `Stack` model, so scoped tokens can never resolve a stack outside their authorization.

### Proof of Concept
1. Create (or reuse) an `ApiClient` scoped to `stack_id: <stack A>` with `permissions: ['read:stack']` (mirrors the `here_come_the_walrus` fixture).
2. Using that client's `authentication_token`, issue: `GET /api/1/stacks/<stack B>/ccmenu.xml?token=<token>` where `<stack B>` is a different stack the client was never scoped to.
3. Observe `require_permission :read, :stack` passes (the client does have `read:stack`), and `CCMenuController#stack` resolves stack B via `Stack.from_param!(params[:stack_id])`, returning stack B's CI status/lock state — confirming cross-stack disclosure with a token that should have been confined to stack A.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-39)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack

      class NoDeploy
        def id
          0
        end

        def ended_at
          Time.now.utc
        end

        def running?
          false
        end
      end

      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
    end
  end
end
```

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
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
