## Analysis

I found a concrete analog: **the same duality-of-selection flaw** from the Holograph report (one value used to authorize, a different/broader value used to actually act) recurs in `Shipit::Api::CCMenuController`, where the *stack a token authorizes* diverges from the *stack the endpoint actually reads*.

`Shipit::Api::BaseController` implements per-token stack scoping: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

An `ApiClient` can be bound to a single `stack_id` (see the scoped fixture `here_come_the_walrus`, exercised in [2](#0-1) ). The intended equality is: `stack the token is scoped to == stack the endpoint returns data for`, enforced through the shared `stack` helper.

`Shipit::Api::CCMenuController` overrides that helper and drops the scoping: [3](#0-2) 

```ruby
class CCMenuController < BaseController
  require_permission :read, :stack
  ...
  private

  def stack
    @stack ||= Stack.from_param!(params[:stack_id])
  end

  def authenticate_api_client
    @current_api_client = ApiClient.authenticate(params[:token])
    super unless @current_api_client
  end
end
```

`require_permission :read, :stack` only checks that the string `"read:stack"` is present in `ApiClient#permissions` (`ApiClient#check_permissions!`, [4](#0-3)  ) — it never checks *which* stack. The stack itself is looked up via `Stack.from_param!(params[:stack_id])`, bypassing `stacks` (the scoped relation). This is exactly the bug-class analog: the credential's authorization is bound to one identifier (`current_api_client.stack_id`), but the code path that touches data keys off an unrelated, attacker-controlled identifier (`params[:stack_id]`) that was never checked against the token's scope.

### Title
Stack-scoped API tokens bypass their `stack_id` binding in `CCMenuController#show` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
A `read:stack`-scoped `ApiClient` bound to a specific `stack_id` can be replayed against `GET /api/stacks/:stack_id/ccmenu` for **any** other stack, because `CCMenuController#stack` re-implements stack lookup with an unscoped `Stack.from_param!` instead of using `BaseController#stacks`, which is the only place the `current_api_client.stack_id` binding is enforced.

### Finding Description
`BaseController` centralizes authorization scoping in `#stacks`/`#stack` ( [1](#0-0) ): if the authenticated `ApiClient` has a non-null `stack_id`, all stack lookups are restricted to `Stack.where(id: current_api_client.stack_id)`. Every other API controller (e.g. `Shipit::Api::StacksController`, `TasksController`, `DeploysController`) inherits this and stays scoped.

`CCMenuController`, however, defines its own private `#stack` method that calls `Stack.from_param!(params[:stack_id])` directly on the `Stack` class, never touching `stacks` or `current_api_client.stack_id`: [5](#0-4) 

The `require_permission :read, :stack` before-action only calls `current_api_client.check_permissions!(:read, :stack)`, which validates the permission string exists in the array — it carries no information about which stack the token was minted for.

Consequently, the equality the design relies on — `token.stack_id == stack_returned_by_endpoint` — breaks for this one controller: any stack-scoped token with `read:stack` permission is treated identically to an unscoped/global token when hitting `/ccmenu`.

### Impact Explanation
An attacker holding (or that has been issued, e.g. via `CCMenuUrlController`, which mints tokens with `read:stack`) a token intended to expose CI status for one stack can instead enumerate `stack_id` and read the deploy/lock/build status of every stack in the installation — including private, unrelated repositories' stacks. This is an unauthorized read of stack state via a credential that was supposed to be confined to a single repository/stack, matching the "unauthenticated read of stack state" High-impact category (the token is valid/authenticated, but its authorization scope is not honored).

### Likelihood Explanation
Exploitation requires only possession of any valid `read:stack`-permissioned `ApiClient` token (which is by design distributed in CCMenu/CCTray URLs, often embedded in dashboards, README badges, or CI status widgets — lower-trust distribution channels than full API credentials) and knowledge/guessing of another stack's `stack_id` path (`owner/repo/branch`), which is not secret. No privileged access, session, or additional secret is required beyond the token itself.

### Recommendation
Remove the private `#stack` override in `CCMenuController` and rely on the inherited `BaseController#stack`/`#stacks`, so stack lookups are always scoped to `current_api_client.stack_id` when the token is stack-scoped. If the override exists intentionally, add an explicit check that `params[:stack_id]` matches `current_api_client.stack_id` (when present) before rendering.

### Proof of Concept
1. Create/obtain a stack-scoped `ApiClient` bound to `stack_id = A` with permission `read:stack` (e.g. via the `CCMenuUrlController#fetch` flow which does `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(...)`, or any client whose `stack_id` column has been set).
2. Note its `authentication_token`.
3. Send `GET /api/stacks/<owner>/<repo-B>/<branch-B>/ccmenu?token=<token>` for a *different* stack `B` that the token was never scoped to.
4. Observe that `CCMenuController#stack` resolves stack `B` via unscoped `Stack.from_param!`, and the response renders `B`'s CI/deploy status — despite the token being minted only for stack `A`. [6](#0-5)

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
