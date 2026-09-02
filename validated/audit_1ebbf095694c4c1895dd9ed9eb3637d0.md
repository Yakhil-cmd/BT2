Confirmed. This is a genuine analog to the M-13 bug class: a binding check that uses a different scope than the one actually enforced downstream, so a value gated by one constraint ends up unconstrained where it is actually used.This confirms the API mount at `/api/stacks/*stack_id/ccmenu` [1](#0-0) , which is authenticated by `Api::CCMenuController` using a bearer token in the `token` query parameter rather than HTTP Basic auth [2](#0-1) .

### Title
Stack-scoped API token bypasses its stack binding on the CCMenu endpoint, allowing cross-stack state disclosure - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`ApiClient` records can be scoped to a single `Stack` via the `stack` association, and this scope is meant to be the authorization boundary for any token: `Shipit::Api::BaseController#stacks` restricts lookups to `Stack.where(id: current_api_client.stack_id)` whenever `current_api_client.stack_id?` is true, and `#stack` resolves the requested `stack_id` param only within that restricted relation [3](#0-2) . `Shipit::Api::CCMenuController`, however, overrides `#stack` to look the target stack up directly from `Stack.from_param!(params[:stack_id])`, completely bypassing the `stacks` scoping helper [4](#0-3) . The only gate left on the action is `require_permission :read, :stack`, which only checks that the token's `permissions` array contains `read:stack` — it never checks which stack the token is bound to [5](#0-4) .

### Finding Description
This is the same class of bug as the ExternalLending report: a limiting condition (`oracleData.maxExternalDeposit`) is computed and enforced in one place but the value that is actually consumed downstream (`targetAmount` versus the real `currentExternalUnderlyingLend`) is not constrained by the same invariant, so the "authorized" quantity and the "acted-upon" quantity diverge. Here the equality that should hold is:

`stack the ApiClient token authorizes (current_api_client.stack_id) == stack the controller action touches (stack)`

Everywhere else in the API (`StacksController`, `TasksController`, `DeploysController`, etc.) this equality is enforced because they all resolve `stack` through `BaseController#stack`/`#stacks`, which filters by `current_api_client.stack_id` [3](#0-2) . `CCMenuController` breaks the equality: it keeps the `read:stack` permission check (so a token bound to *some* stack with `read:stack` still passes `before_action`), but resolves the actual target stack independently of that binding [6](#0-5) .

Before the attack: a stack-scoped token (e.g. fixture `here_come_the_walrus`, bound to a single stack with `read:stack` permission) can only read that one stack through the normal API, as demonstrated by the test asserting a stack-scoped client "will only see that one stack" [7](#0-6) .

After the attack: the same token, presented as `?token=<authentication_token>` to `GET /api/stacks/*stack_id/ccmenu`, passes `authenticate_api_client` (token is valid) [2](#0-1) , passes `require_permission :read, :stack` (permission array contains `read:stack`, scope not checked) [8](#0-7) , and then `stack` resolves *any* `stack_id` supplied in the URL via `Stack.from_param!`, not just the one the token is bound to [4](#0-3) .

### Impact Explanation
This is unauthenticated (relative to the target stack) read of stack state: a token deliberately restricted to a single, presumably lower-sensitivity stack can be used to read the deploy/rollback status (via `deploys_and_rollbacks.last`) of every other stack managed by the Shipit instance, including private repositories the token's creator/scope should not have visibility into. This matches the "unauthenticated read of stack state" High-impact category, since the stack-scope restriction is the authorization mechanism that is being bypassed.

### Likelihood Explanation
Any holder of a stack-scoped API token with the common `read:stack` permission (the same permission granted to CCMenu clients created by `CCMenuUrlController`) can exploit this with a single unauthenticated GET request by supplying an arbitrary `stack_id`; no privileged account, session, or additional secret is required beyond the token itself.

### Recommendation
Have `Api::CCMenuController#stack` resolve the stack through the same `stacks` scoping helper used by `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the stack binding enforced by `current_api_client.stack_id` is respected consistently with every other API controller.

### Proof of Concept
1. Create (or use fixture) `ApiClient` scoped to `stack: A` with `permissions: ['read:stack']`, and obtain its `authentication_token`.
2. As this token's holder, issue `GET /api/stacks/<owner>/<repo>/<env-of-stack-B>/ccmenu?token=<token>` where stack B is a different stack the token was never granted access to.
3. Observe that `authenticate_api_client` succeeds (`ApiClient.authenticate(params[:token])` finds the record) [2](#0-1) , `require_permission :read, :stack` passes because it only checks the permissions array [5](#0-4) , and `stack` in `show` resolves to stack B via the unscoped `Stack.from_param!` lookup [9](#0-8) , returning stack B's CCMenu XML (build status, last deploy time, etc.) despite the token never being authorized for stack B.

### Citations

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-31)
```ruby
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
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
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
