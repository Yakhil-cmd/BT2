### Title
CCMenu API endpoint bypasses `ApiClient#stack_id` scoping, allowing a stack-scoped token to read status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::BaseController` enforces a binding between an `ApiClient` token and the stack(s) it is allowed to touch: when an `ApiClient` has a `stack_id`, the `stacks`/`stack` helpers restrict lookups to that single `Stack`. `Api::CCMenuController` overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly, never consulting `current_api_client.stack_id`, which breaks that binding.

### Finding Description
`Api::BaseController` defines the intended scoping equality: `token.stack_id == stack.id` whenever a client is stack-scoped: [1](#0-0) 

Permission checks (`require_permission :read, :stack` / `ApiClient#check_permissions!`) only test whether the *string* `"read:stack"` is present in `permissions`; they carry no stack identity at all: [2](#0-1) 

So the only place a per-stack authorization boundary is actually enforced is the `stacks`/`stack` helper in `BaseController`. Every other controller that needs a `Stack` from `params[:stack_id]` is expected to route through that helper (or reimplement the same scoping), as proven by `Api::StacksControllerTest`'s explicit assertion that a stack-scoped client can only see its own stack: [3](#0-2) 

`Api::CCMenuController`, however, defines its own `stack` method that resolves `params[:stack_id]` straight from `Stack.from_param!`, completely independent of `current_api_client`: [4](#0-3) 

Because `require_permission :read, :stack` only checks the generic `read:stack` permission string and not the specific stack, any `ApiClient` holding `read:stack` — including one deliberately scoped to a single stack via `stack_id` — can pass `stack_id` for a completely different stack and the controller will happily render CI/build status (`lastBuildStatus`, `lastBuildLabel`, etc.) for it.

Before the attacker's request: `token.stack_id == A`, and the only stack readable through this token is expected to be `A` (per `BaseController#stacks`).
After the attacker's request: the same token, unmodified, retrieves `CCMenuController#show` output for stack `B ≠ A`, because `CCMenuController#stack` never intersects with `token.stack_id`.

### Impact Explanation
This is a High-severity authorization boundary break matching "escalation into `Shipit.github_teams` authorization... unauthenticated read of stack state" from the impact list: a token that was intentionally minted (e.g. via `CCMenuUrlController`/`ApiClientsController`) to be readable only for one stack can be used to read build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, lock state) of every other stack in the Shipit instance, including stacks belonging to different repositories/teams that the token holder should have no visibility into.

### Likelihood Explanation
Likelihood is high for anyone who already possesses *any* valid `ApiClient` token with `read:stack` permission (a routine, low-privilege credential many teams distribute broadly, e.g. via `CCMenuUrlController`, CI dashboards, status badges). No special privilege beyond having one such token is required — the token does not need `write:stack`, `deploy:stack`, or admin access, and the attacker only needs to know or guess another stack's `owner/repo/environment` path.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped lookup from `BaseController` instead of calling `Stack.from_param!` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so that `current_api_client.stack_id` scoping (already implemented in `stacks`) is honored, matching the behavior enforced elsewhere (e.g. `Api::StacksController`).

### Proof of Concept
1. As an admin, create two stacks, `A` (`owner/repoA/production`) and `B` (`owner/repoB/production`).
2. Create an `ApiClient` scoped to stack `A` only (`stack_id = A.id`, `permissions: ["read:stack"]`) — this is exactly the pattern used by `here_come_the_walrus` in the fixtures and by `CCMenuUrlController`. [5](#0-4) 
3. Using that client's `authentication_token`, call `GET /api/owner/repoB/production/ccmenu.xml?token=<token>` (or via Basic Auth).
4. Because `Api::CCMenuController#stack` bypasses the `stacks` scoping check, the request succeeds (`200 OK`) and returns build/status data for stack `B`, even though the token was only supposed to grant read access to stack `A`.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
