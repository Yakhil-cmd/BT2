### Title
Api::CCMenuController#stack bypasses ApiClient stack scoping, letting a stack-scoped token read any other stack's deploy status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` tokens can be scoped to a single stack via `stack_id`, and `Api::BaseController#stacks`/`#stack` enforce that scope for every other API controller. `Api::CCMenuController` overrides `#stack` to resolve directly from `Stack.from_param!(params[:stack_id])`, skipping the `current_api_client.stack_id?` restriction entirely, so any valid, permission-checked token can be used to read deploy state for a stack it was never bound to.

### Finding Description
`Api::BaseController` defines the trust boundary between "which stacks a token is authorized to touch" and "which stack is being acted on": [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is scoped; `stack` is built on top of `stacks.from_param!`, so every controller inheriting this method is bound by the token's `stack_id`.

`Api::CCMenuController`, however, defines its own private `stack` method that talks directly to `Stack.from_param!(params[:stack_id])`, completely bypassing `current_api_client.stack_id`/`stacks`: [2](#0-1) 

The only authorization check that remains is `require_permission :read, :stack`, which validates the permission string via `ApiClient#check_permissions!` but has no notion of which stack the client is scoped to: [3](#0-2) 

Fixture evidence shows tokens are routinely created stack-scoped (e.g. `here_come_the_walrus` is bound to the `shipit` stack with `read:stack`): [4](#0-3) 

and this scoping is actively relied upon and tested for the sibling `StacksController`: [5](#0-4) 

The equality broken here is: **"the stack a token authorizes" (`current_api_client.stack_id`) vs. "the stack the request actually touches" (`params[:stack_id]` used unchecked in `CCMenuController#stack`)**. Before the request, both sides are equal by design (`stacks.from_param!` enforces it everywhere else). After a request to `GET /api/stacks/*stack_id/ccmenu` with `token` set to any stack-scoped client and an arbitrary `stack_id`, the two sides diverge: the token authorizes only stack A, but the controller returns deploy/task state for whatever stack the caller names in the URL.

### Impact Explanation
An unprivileged holder of any `read:stack`-permissioned `ApiClient` token — even one deliberately scoped to a single, low-sensitivity stack (this is the exact intended use case shown by `CCMenuUrlController`, which mints per-stack CCMenu tokens) — can read the deploy/task status (`deploys_and_rollbacks.last`, rendered via the `shipit/ccmenu/project` XML view including commit/task/user info) of any other stack in the installation, including stacks the token owner has no legitimate access to. This is an unauthenticated-scope escalation / unauthorized read of stack state, matching the "escalation into `Shipit.github_teams` authorization" / "unauthenticated read of stack state" High-impact category, because the stack-scoping mechanism is the only authorization control differentiating "this token may see stack A" from "this token may see any stack."

### Likelihood Explanation
Likelihood is high for anyone already in possession of a legitimately-issued, stack-scoped `read:stack` token (these are handed out via the CCMenu URL feature to CI dashboards, build-status tools, etc. — inherently lower-trust consumers than full Shipit users). No additional secret or privilege is required beyond swapping the `stack_id` path segment in the request URL; the permission check (`read:stack`) still passes because it does not consider `stack_id` at all.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` (or reimplement it via `stacks.from_param!(params[:stack_id])` as the base controller does) so that stack-scoped `ApiClient` tokens cannot resolve a different stack than the one they are bound to. Add a regression test asserting that a `stack_id`-scoped client receives a 404/403 when it requests `/api/stacks/:other_stack/ccmenu`.

### Proof of Concept
1. Create (or use) an `ApiClient` scoped to `stack: A` with `permissions: ['read:stack']` (e.g. via `CCMenuUrlController#fetch` for stack A, or the `here_come_the_walrus` fixture pattern).
2. As the holder of that token, issue: `GET /api/stacks/<owner_b>/<repo_b>/<env_b>/ccmenu?token=<token-scoped-to-A>` where `owner_b/repo_b/env_b` is a different stack B.
3. `authenticate_api_client` succeeds (token is valid), `require_permission :read, :stack` passes (`read:stack` is present), and `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` directly — returning stack B's data instead of raising the `stacks.from_param!` scoping restriction that other API endpoints (`Api::StacksController`, `Api::TasksController`, etc.) enforce.
4. Response includes stack B's latest deploy/task status via the `shipit/ccmenu/project` XML view, even though the token was never authorized for stack B.

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
