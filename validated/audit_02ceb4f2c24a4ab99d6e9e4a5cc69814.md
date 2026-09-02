### Title
Stack-scoped API token bypasses its `stack_id` restriction on CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
An `ApiClient` can be scoped to a single `Stack` via its `stack_id` column, so that a token with `read:stack` permission should only be able to read that one stack. `Shipit::Api::CCMenuController` overrides the `stack` accessor to bypass this scoping, resolving the target stack directly from the global `Stack` relation instead of the token-scoped one, letting a stack-scoped token read the build/deploy status of any stack in the installation.

### Finding Description
`Shipit::Api::BaseController` implements per-token stack scoping through two cooperating methods: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the token is bound to a specific stack (`current_api_client.stack_id?`), and `stack` resolves the requested `params[:stack_id]` only from within that restricted relation. All the other API controllers (`CommitsController`, `TasksController`, `LocksController`, `MergeRequestsController`, `OutputsController`, `HooksController`, etc.) rely on this inherited `stack` method, so `require_permission :read, :stack` (a check of the string permission `"read:stack"` on `ApiClient#permissions`) combined with the `stacks`-scoped lookup jointly enforce the binding: `token.stack_id == accessed_stack.id` (when the token is stack-bound).

`CCMenuController` breaks this binding: [2](#0-1) 

Its private `stack` method is overridden to call `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, entirely skipping the `stacks` method that applies `current_api_client.stack_id?` filtering. The controller still runs `require_permission :read, :stack`, but `ApiClient#check_permissions!` only checks that the string `"read:stack"` is present in the client's permission list: [3](#0-2) 

It never checks whether `current_api_client.stack_id` matches the stack being requested. As a result, an `ApiClient` created with a `stack_id` that scopes it to Stack A, and with `read:stack` permission, can call `GET /api/ccmenu/:any_other_stack` and receive that other stack's build data, even though the base-controller design intends such a token to only "authorise" reads on its own bound stack.

### Impact Explanation
This crosses the "stack a token authorises versus a stack it touches" trust boundary: the token's `stack_id` is the authorization boundary the operator configures when issuing narrowly-scoped API credentials (e.g., to a third-party CI dashboard that should only see one stack's build status), but the code lets that token touch every other stack. The leaked data (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `activity`, `webUrl`, lock state) is stack deploy/task state, matching the High-impact category "unauthenticated read of stack state, task streams or deploy output" — here the read is unauthorized rather than fully unauthenticated, but it is achieved by a token that was deliberately restricted to a different stack, which is the core of the intended trust boundary.

### Likelihood Explanation
Any holder of a valid, stack-scoped `read:stack` API token (a routine, low-privilege credential meant to be handed to build-status dashboards/CI tools) can trigger this by simply changing the `stack_id` path segment on the `/api/ccmenu/*` route to another stack's identifier. No other credential, secret, or privileged access is required beyond the token itself, which the scoping mechanism was specifically designed to make safe to distribute narrowly.

### Recommendation
Remove the `stack` override in `CCMenuController`, or reimplement it to resolve the stack through the inherited `stacks` (token-scoped) relation, e.g. `stacks.from_param!(params[:stack_id])`, so stack-scoped tokens cannot read other stacks' data.

### Proof of Concept
1. Create two stacks, `stack_a` and `stack_b`.
2. Create an `ApiClient` with `stack_id: stack_a.id` and `permissions: ['read:stack']`.
3. Authenticate as that client and request `GET /api/ccmenu/<stack_b_to_param>` with its token.
4. The response returns HTTP 200 with `stack_b`'s CCMenu XML (`lastBuildStatus`, etc.), even though the token is scoped to `stack_a` — confirmed by the controller's `stack` method at [4](#0-3)  which never filters by `current_api_client.stack_id`, unlike `BaseController#stacks` at [1](#0-0) .

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-38)
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
