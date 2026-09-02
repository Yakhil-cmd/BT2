## Analysis

The Lido bug class is a **verification/authorization check that is computed against one scope of data, while the actual effect happens against a different (broader) scope** — the sanity check trusted a delta that didn't account for the real state touched by the burn. The closest reachable analog in `shipit-engine` is the binding: *the stack an `ApiClient` token is authorized for* vs. *the stack the endpoint actually resolves and returns data for*.

`Shipit::Api::BaseController` establishes the canonical scoping contract: [1](#0-0) 

Any stack-scoped `ApiClient` (one created with a non-nil `stack_id`, e.g. the `here_come_the_walrus` fixture) is restricted to `Stack.where(id: current_api_client.stack_id)`, and `stack` resolves through that scoped relation via `from_param!`.

`Shipit::Api::CCMenuController`, however, overrides `stack` and bypasses this scoping entirely: [2](#0-1) 

`require_permission :read, :stack` at [3](#0-2)  only calls `ApiClient#check_permissions!`, which checks the *operation:scope* string (`"read:stack"`) but never checks *which* stack the token is bound to: [4](#0-3) 

So the equality the system is supposed to enforce, `token.stack_id == stack.id` (or `token.stack_id.nil?` for unscoped tokens), is checked by `BaseController#stack`/`#stacks` but is **not** checked by `CCMenuController#stack`, which instead does `Stack.from_param!(params[:stack_id])` against every stack in the installation.

### Title
Stack-scoped `ApiClient` token bypasses its stack binding in `Api::CCMenuController#show` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` authenticates callers with a `read:stack`-scoped `ApiClient` token (via Basic Auth or a `token` query param) but resolves the target `Stack` with `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!` used by every other API controller. A token that was minted for one specific stack (`ApiClient#stack_id` set) can therefore be replayed with an arbitrary `stack_id` in the URL to read CCMenu build-status XML for any stack in the installation.

### Finding Description
`ApiClient` supports per-token stack scoping via the `stack_id` column, enforced centrally in `BaseController#stacks`/`#stack`: [1](#0-0) 

`ApiClient#check_permissions!` only validates the coarse `operation:scope` permission string (e.g. `read:stack`) and has no notion of *which* stack is being accessed: [4](#0-3) 

The stack-identity check therefore lives entirely in the `stack`/`stacks` helper methods of `BaseController`. `CCMenuController` redefines `stack` to skip that helper and query `Stack.from_param!(params[:stack_id])` directly against all stacks: [2](#0-1) 

Because `require_permission :read, :stack` never re-derives `stack` through the scoped `stacks` collection, a valid token whose `stack_id` binds it to Stack A satisfies `require_permission!` (it has `read:stack` permission at all) and then is used to render CCMenu data for whatever `stack_id` the caller supplies in the URL — Stack B, C, etc. This is the same class of bug as LID-18: the check that is supposed to gate the operation (`is this token allowed to touch this stack?`) is evaluated against the wrong scope (the token's *existence*/permission list) rather than the scope the operation actually acts on (the specific stack fetched via the unscoped `Stack.from_param!`).

### Impact Explanation
An attacker who obtains a single stack-scoped, read-only CCMenu-style API token (these are commonly embedded in third-party CI-dashboard tool configs and are treated by operators as "read-only, single-stack" credentials) can use it to read CCMenu build state — activity, last build status, last build label (commit SHA), and web URL — for **every** stack managed by the Shipit instance, not just the one it was issued for. This is an authorization-scope escalation: read access to stack state that should have been confined to one stack extends to all stacks, matching the "unauthorized read of stack state" High-impact category.

### Likelihood Explanation
Likelihood is limited by the precondition that a stack-scoped `ApiClient` token must exist and be known to the attacker. The current UI (`ApiClientsController#create_params`) does not expose a way to set `stack_id`, so today stack-scoped tokens are only created programmatically/by integrations (as shown by the `here_come_the_walrus` fixture). Wherever such scoped tokens are provisioned (e.g., future features, console-created integrations, or forks that expose stack-scoping in the UI), any holder of one such token gets free-form cross-stack read access through this single endpoint, so the likelihood is tied to the presence of scoped tokens in a given deployment rather than to any additional attacker capability.

### Recommendation
Make `CCMenuController#stack` resolve through the same scoped collection as every other API controller (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!`, so the token's `stack_id` binding is enforced consistently with `BaseController`.

### Proof of Concept
1. Provision (or obtain) an `ApiClient` scoped to Stack A: `ApiClient.create!(creator: user, name: 'x', stack_id: stack_a.id, permissions: ['read:stack'])`, and get its `authentication_token`.
2. Call `GET /api/*stack_a_id/ccmenu.xml` with that token via Basic Auth or `?token=` — succeeds as expected, per [5](#0-4) .
3. Call `GET /api/*stack_b_id/ccmenu.xml` using the **same** token, substituting Stack B's `to_param` for `stack_id`. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` unscoped, this request also succeeds and returns Stack B's build status/name/webUrl, even though the token was only ever authorized for Stack A. Contrast with `Api::StacksController#show`/`#index`, which use the scoped `stacks` method at [1](#0-0)  and correctly reject/omit Stack B for the same token.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
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
