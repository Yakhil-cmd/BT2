### Title
API token scoped to one stack can read CI status of any stack via CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` scopes stack lookups to the stack an `ApiClient` token was authorized for, but `Shipit::Api::CCMenuController` overrides the `stack` accessor with an unscoped lookup, breaking the binding between "the stack a token authorizes" and "the stack the request actually touches."

### Finding Description
`ApiClient` supports being scoped to a single stack (`belongs_to :stack, optional: true`) [1](#0-0) . `Shipit::Api::BaseController` enforces this scoping generically: the `stacks` helper restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated client is stack-scoped, and `stack` resolves the requested `params[:stack_id]` only from within that restricted set: [2](#0-1) 

`Api::CCMenuController` inherits from `BaseController` and requires the `read:stack` permission, relying on `check_permissions!` for authorization [3](#0-2) . However, it locally redefines `stack`, bypassing the `stacks` scoping entirely and resolving directly against the global `Stack` relation: [4](#0-3) 

`check_permissions!` only validates that the token carries the `read:stack` permission string; it never checks that the resolved `stack` matches `current_api_client.stack_id`: [5](#0-4) 

So the binding that should hold is:
`current_api_client.stack_id (the stack the token authorizes) == stack (the stack the request touches)`

Before the flaw (as implemented in `BaseController#stack`), this equality is enforced because `stacks` is filtered by `current_api_client.stack_id?`. In `CCMenuController`, the override drops that filter, so for any stack-scoped token with `read:stack` permission, `stack != current_api_client.stack` is achievable simply by supplying a different `stack_id` in the URL — the binding is broken.

### Impact Explanation
This satisfies the High-impact category "unauthenticated read of stack state, task streams or deploy output" once scoped to the wrong tenant: a token that was explicitly minted to expose only one stack's CI status (e.g. via `CCMenuUrlController`, which mints per-stack read-only tokens for embedding in third-party CI dashboards) can be replayed against `Api::CCMenuController#show` for any other stack ID to leak that stack's `lastBuildStatus`, `lastBuildLabel`, `activity`, and lock state — data belonging to a different repository/stack the token holder was never meant to see.

### Likelihood Explanation
Likelihood is High for any deployment that uses the CCMenu integration (`CCMenuUrlController` documents this as a supported, low-privilege token-issuance flow) since it requires only possession of a legitimately-issued, narrowly-scoped `read:stack` CCMenu token and knowledge/guessing of another stack's `to_param` — no elevated credentials, webhook secret, or session are needed beyond the token itself.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` (or reimplement it using the inherited `stacks` relation) so that stack-scoped tokens are restricted the same way as in `BaseController`, i.e. `@stack ||= stacks.from_param!(params[:stack_id])`.

### Proof of Concept
1. Admin visits Stack A's page; `CCMenuUrlController#fetch` creates (or reuses) an `ApiClient` with `permissions: ['read:stack']`. If that client is scoped to Stack A (`stack_id` set), the intent is that its token can only report on Stack A.
2. Attacker (holder of Stack A's CCMenu URL/token, e.g. anyone who can view the CI dashboard embed) sends: `GET /api/stacks/<STACK_B_ID>/ccmenu.xml?token=<stack-A-token>`.
3. `authenticate_api_client` in `CCMenuController` succeeds via `ApiClient.authenticate(params[:token])` [6](#0-5) .
4. `require_permission :read, :stack` passes because the token has `read:stack` regardless of which stack it was scoped to [7](#0-6) .
5. `stack` resolves `STACK_B_ID` via the unscoped `Stack.from_param!` [8](#0-7) , and `show` renders Stack B's deploy/build status — data the Stack-A-scoped token was never authorized to read.

### Citations

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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

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
