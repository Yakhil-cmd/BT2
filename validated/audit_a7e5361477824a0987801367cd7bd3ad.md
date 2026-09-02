Found it. `Shipit::Api::CCMenuController` overrides `stack` to look up **any** stack by ID via `Stack.from_param!(params[:stack_id])`, bypassing the `stack_id`-scoped lookup used everywhere else in the API (`BaseController#stacks`/`#stack`, which restricts the query to `Stack.where(id: current_api_client.stack_id)` when the client is scoped to a stack). This is exactly the "stack a token authorises versus stack it touches" binding mismatch called out in the rules.

### Title
CCMenu API token scoped to one stack can read status/tokens of any stack - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`CCMenuController` defines its own `stack` method that ignores the ApiClient's `stack_id` scoping and loads any stack from the raw `params[:stack_id]`, while `require_permission :read, :stack` only checks the client possesses the generic `read:stack` permission string, not that the specific stack matches the token's `stack_id`.

### Finding Description
`Shipit::Api::BaseController` establishes the equality that should hold for every scoped API client: `token.stack_id == stack.id` (or `token.stack_id.nil?` for unscoped clients), enforced via: [1](#0-0) 
which is used by `stack` (`stacks.from_param!(...)`), so a stack-scoped client (e.g. `here_come_the_walrus` fixture, scoped to the `shipit` stack) can never resolve a `Stack` object outside its own `stack_id`.

`CCMenuController`, however, overrides this method: [2](#0-1) 
calling `Stack.from_param!(params[:stack_id])` directly against the whole `Stack` table, with no reference to `current_api_client.stack_id`. The only authorization check applied is `require_permission :read, :stack`: [3](#0-2) 
which just calls `ApiClient#check_permissions!`, a pure string-membership check against `permissions`: [4](#0-3) 
It never compares `operation`/`scope` against the token's bound `stack_id`. Any client holding the `read:stack` permission — including one deliberately scoped to a single stack via `stack_id` — can therefore pass any other stack's `to_param` as `stack_id` and have `Stack.from_param!` resolve it, exactly mirroring the analog bug class: a binding (`token.stack_id == accessed.stack_id`) that is asserted for the rest of the API surface but silently dropped for this one endpoint, similar to how `TransitionLoanManager.add` dropped the accrued-interest tracking that the rest of the accounting model assumed held.

Additionally, `CCMenuController#authenticate_api_client` is overridden to authenticate solely via `params[:token]` (a query string), bypassing the Basic-Auth header flow, but that alone is documented/intended behavior for CCMenu clients (see `CCMenuUrlController`), so the core issue is the scoping bypass in `stack`, not the alternate auth transport.

### Impact Explanation
This qualifies as High severity per the rules ("unauthenticated read of stack state ... deploy output" analog — here, authorized-but-scope-violating read): an attacker holding a legitimately-issued, stack-scoped `ApiClient` token (e.g. a CCMenu client created via `CCMenuUrlController#client`, which is created with only `%w[read:stack]` and no stack restriction is enforced at read time) can enumerate and read the CI/deploy status (`shipit/ccmenu/project.xml`, including `lastBuildStatus`, `lastBuildLabel`, `webUrl`, lock state) of **every** stack in the Shipit instance, not just the one it was provisioned for.

### Likelihood Explanation
High. Exploitation requires only possessing any valid `read:stack`-permissioned API token (these are handed out routinely, e.g. automatically per-stack by `CCMenuUrlController`) and knowing/guessing another stack's `to_param` (`owner/repo/branch`), which is not secret information; no additional privilege or credential is required.

### Recommendation
Remove the `stack` override in `CCMenuController` (or reintroduce the scoping) so it uses the same `stacks.from_param!(params[:stack_id])` pattern as `BaseController`, ensuring `Stack.from_param!` is always constrained by `current_api_client.stack_id` when the client is stack-scoped.

### Proof of Concept
1. As an admin, create (or have auto-created) a CCMenu `ApiClient` scoped to `stack_id: shipit_stack.id` with `permissions: ['read:stack']` (mirrors fixture `here_come_the_walrus`).
2. Using that client's `authentication_token`, call `GET /api/stacks/:other_owner/:other_repo/:other_branch/ccmenu.xml?token=<token>` where `other_owner/other_repo/other_branch` is a *different* stack than the one the token is scoped to.
3. Observe the request succeeds (`200 OK`) and returns the other stack's CI project status, despite the token being scoped to a different `stack_id` — contrasted with the same token used against `Api::StacksController#show`, which correctly returns nothing/403 for stacks outside its scope.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-7)
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
