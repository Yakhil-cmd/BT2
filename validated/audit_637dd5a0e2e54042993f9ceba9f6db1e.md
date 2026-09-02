### Title
Api::CCMenuController bypasses ApiClient stack scoping, letting a stack-restricted token read any stack's build/deploy status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` supports being scoped to a single stack via its `stack_id` column, and `Api::BaseController` enforces that scope for every endpoint that resolves the target stack through the shared `stack`/`stacks` helpers. `Api::CCMenuController` overrides `stack` and resolves the target record directly from `Stack.from_param!`, skipping the scoping helper entirely, so the "stack a token authorizes" and the "stack it touches" are no longer the same value for this endpoint.

### Finding Description
`Api::BaseController` defines the authorization binding between an `ApiClient` and the stacks it may touch: [1](#0-0) 

`current_api_client.stack_id?` restricts the resolvable stack set to the single stack the client was scoped to at creation time (confirmed by fixtures and tests, e.g. `here_come_the_walrus` scoped to the `shipit` stack): [2](#0-1) [3](#0-2) 

`Api::CCMenuController`, however, overrides `stack` to bypass that scoping and fetch by parameter alone, while still relying on `check_permissions!`, which only checks the permission *name* (`read:stack`) and never the stack identity: [4](#0-3) [5](#0-4) 

So the equality that should hold — "stack authorized for this `ApiClient.stack_id`" == "stack acted upon in `#show`" — is broken specifically in this controller: every other API resource (`Api::StacksController`, `Api::LocksController`, `Api::TasksController`, etc.) goes through `Api::BaseController#stack`/`#stacks`, which enforces the binding, but `CCMenuController#stack` does not.

### Impact Explanation
A client holding a token for an `ApiClient` scoped to stack A with only `read:stack` permission (a legitimate, minimally-privileged, single-stack integration credential — the exact use case the `stack_id` scoping exists for) can call `GET /api/stacks/<stack B>/ccmenu` and obtain stack B's build/deploy state (last build status, activity, lock status, web URL) even though its token was never authorized for stack B. This is an authorization-scope escalation: the credential crosses the stack boundary it was explicitly restricted to, yielding unauthorized read of another repository/stack's deploy state, matching the High-impact bucket "escalation into ... authorization, unauthenticated read of stack state, task streams or deploy output."

### Likelihood Explanation
Any holder of a valid, stack-scoped `ApiClient` token (an intended, low-privilege credential type) can trigger this by simply changing the `stack_id` path segment on the CCMenu request — no additional secret, signature, or elevated access is required beyond the token they already legitimately possess for their own stack.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` collection from `Api::BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the `ApiClient.stack_id` restriction is enforced consistently with every other API controller.

### Proof of Concept
1. Create/observe an `ApiClient` scoped to Stack A (`stack_id` set, e.g. via the `here_come_the_walrus` pattern) with permission `read:stack`.
2. Using that client's `authentication_token`, issue `GET /api/stacks/<stack-B-owner>/<stack-B-repo>/<stack-B-env>/ccmenu` (or via the `token` query param, as `CCMenuController#authenticate_api_client` also accepts `params[:token]`).
3. Observe a `200 OK` response rendering Stack B's CCMenu XML (name, activity, lastBuildStatus, etc.), despite the client being scoped only to Stack A — confirmed by contrast with `Api::StacksController`, where the same client would be limited to Stack A per `stacks`/`stack` scoping.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-37)
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
