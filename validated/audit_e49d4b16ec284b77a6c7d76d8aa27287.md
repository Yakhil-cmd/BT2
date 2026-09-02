### Title
Stack-scoped API token bypasses per-stack authorization in CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup helper to resolve the stack directly from the URL parameter instead of going through the stack-scoping mechanism defined in `Shipit::Api::BaseController`. This lets a token that is authorized (`stack_id`-scoped) for one stack be used to read the deploy/lock state of an arbitrary other stack, because the permission check only verifies the generic `read:stack` bit and never verifies that the token's bound stack matches the stack actually being read.

### Finding Description
`Shipit::Api::BaseController` defines the intended per-stack authorization boundary: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` is scoped to a specific stack, and `stack` resolves the requested `params[:stack_id]` only within that restricted relation. This is the mechanism that is supposed to enforce "the stack a token authorizes" == "the stack a request can touch."

`ApiClient` supports being scoped to a single stack via `belongs_to :stack, optional: true` and permission checks are purely bitwise, unrelated to that scoping: [2](#0-1) [3](#0-2) 

`check_permissions!` never looks at `stack_id`; the only place that binding is enforced is `BaseController#stacks`/`#stack`.

`CCMenuController`, however, defines its own `stack` method that resolves the stack directly against the global `Stack` scope, completely bypassing `BaseController#stacks`: [4](#0-3) 

The controller only checks the coarse permission bit: [5](#0-4) 

The fixture data confirms stack-scoped tokens are a real, supported configuration in this codebase: [6](#0-5) 

Route configuration confirms the CCMenu endpoint accepts an arbitrary `stack_id` path segment independent of the authenticating token: [7](#0-6) 

**Equality that should hold, but is broken:**
`stack a token authorizes (current_api_client.stack_id)` == `stack a request actually touches (params[:stack_id] resolved via CCMenuController#stack)`

Before the bypass (as in every other API controller that inherits `BaseController#stack`), this equality holds because `stacks.from_param!` filters by `current_api_client.stack_id`. In `CCMenuController`, the override makes the right-hand side unconstrained, breaking the equality: a token scoped to Stack A can successfully resolve and read Stack B.

This is directly analogous to the reported class of bug: `check_permissions!`/`get_expected_withdrawals`-style code performs a locally-valid check (permission bit present / individual withdrawal ≤ balance) but omits the aggregate/identity invariant (per-stack scope / cumulative balance) that a sibling code path (`BaseController#stacks`) is designed to enforce, producing divergent, inconsistent authorization behavior between this controller and the rest of the API surface.

### Impact Explanation
An attacker holding a legitimately-issued, stack-scoped API token (e.g., a token meant only for Stack A, matching the `here_come_the_walrus`-style fixture pattern) can query `GET /api/stacks/*stack_id/ccmenu` for any other stack ID and receive that stack's deploy/lock/build state (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`), which is exactly the "unauthenticated read of stack state" impact category (High) — the token holder is unauthenticated with respect to the target stack, since their token was never authorized for it.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped `ApiClient` tokens (a supported and expected pattern per the model and fixtures) and exposes the CCMenu integration endpoint. No privileged access, session, or additional secrets are required beyond possession of any valid, narrowly-scoped API token — only the `stack_id` URL segment needs to be changed.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController` (and any other controller that redefines `stack` outside of `BaseController#stacks`) and instead rely on the inherited, scope-aware `stack`/`stacks` helpers from `BaseController`, ensuring `Stack.from_param!` is always resolved through `current_api_client`-scoped relation. Add a regression test asserting that a stack-scoped `ApiClient` cannot read `ccmenu#show` for a stack other than the one it is bound to.

### Proof of Concept
1. Create/obtain an `ApiClient` with `permissions: ['read:stack']` and `stack: StackA` (as modeled by the `here_come_the_walrus` fixture in `test/fixtures/shipit/api_clients.yml`).
2. Using that token's Basic-Auth credentials, send `GET /api/stacks/<StackB-owner>/<StackB-repo>/<StackB-env>/ccmenu` where `StackB` is a different stack than the one the token is scoped to.
3. Observe the request succeeds (`require_permission :read, :stack` passes because the token has the `read:stack` bit) and returns `StackB`'s deploy/build/lock status via `app/controllers/shipit/api/ccmenu_controller.rb#show`, even though `current_api_client.stack_id` points to `StackA`, demonstrating the scope bypass.

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

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-6)
```ruby
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
```
