### Title
Stack-scoped ApiClient tokens can read CCMenu status for any stack, bypassing the token's stack binding - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` re-implements the `stack` lookup instead of reusing the scope-aware helper from `Api::BaseController`, so an `ApiClient` token that is restricted to a single stack (`stack_id` set) can be replayed with a different `stack_id` URL parameter to read deploy state of a stack it was never authorized to see. This breaks the binding "a stack a token authorises" (`ApiClient#stack_id`) versus "a stack it touches" (the `Stack` object the controller actually queries).

### Finding Description
`Api::BaseController` implements token-to-stack scoping through two cooperating methods: [1](#0-0) 

`stacks` restricts the queryable set to the single stack referenced by `current_api_client.stack_id` when that attribute is set, and `stack` resolves `params[:stack_id]` only from within that restricted relation. Controllers such as `Api::StacksController`, `Api::CommitsController`, and `Api::LocksController` rely on this `stack` method (or the equally-scoped `stacks` method) to enforce the binding between the authenticated `ApiClient` and the `Stack` it is allowed to touch, and this is explicitly covered by the test "an api client scoped to a stack will only see that one stack": [2](#0-1) 

`Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely and resolve directly against the global `Stack` table using the raw, attacker-supplied `params[:stack_id]`: [3](#0-2) 

The `require_permission :read, :stack` before_action only checks that the token carries the generic `read:stack` permission string via `ApiClient#check_permissions!`: [4](#0-3) 

It never checks `current_api_client.stack_id` against the requested `params[:stack_id]`. Because `CCMenuController#stack` calls `Stack.from_param!` directly instead of `stacks.from_param!`, the stack-scoping check present in the base controller is skipped for this specific action.

### Impact Explanation
Any holder of a valid `ApiClient` token that was deliberately scoped to one stack (e.g. distributed to a CI dashboard or third-party CCMenu client for a specific project) can supply an arbitrary `stack_id` in the request and read `deploys_and_rollbacks` status/output metadata for any other stack in the installation, including stacks belonging to different repositories/teams that the token issuer never intended to expose. This is an unauthorized read of stack/deploy state across a trust boundary the token was explicitly built to enforce — matching the "High: unauthenticated/unauthorized read of stack state, task streams or deploy output" impact class, since it defeats the app's own token-to-stack authorization binding without requiring any additional privilege beyond possessing one legitimately scoped, low-privilege token.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped `ApiClient` tokens (a documented, intended feature — see the `stacks_controller_test.rb` coverage above) and exposes the `/api/stacks/:stack_id/ccmenu.xml`-style endpoint to less-trusted holders (e.g., CI dashboard widgets, external monitoring tools). No privileged account, webhook secret, or session is required — only the scoped token that was already handed out for its intended, narrow purpose.

### Recommendation
Make `Api::CCMenuController#stack` reuse the scope-aware `stacks` relation (i.e., `stacks.from_param!(params[:stack_id])`) exactly like `Api::BaseController#stack`, so a stack-scoped `ApiClient` cannot resolve any stack outside `current_api_client.stack_id`. Alternatively, explicitly re-check `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id` before rendering, and add regression tests analogous to the existing `Api::StacksController` "scoped to a stack will only see that one stack" test but targeting `CCMenuController`.

### Proof of Concept
1. As an admin, create a stack-scoped `ApiClient` for `Stack A` with permission `read:stack` and `stack_id` set to Stack A's id (as done for fixture `here_come_the_walrus` in `test/controllers/api/stacks_controller_test.rb`).
2. Using that token, request `GET /api/stacks/:stack_id/ccmenu.xml?token=<TOKEN>` but with `stack_id` set to the id/param of `Stack B` (a stack the token was never scoped to).
3. Observe that `Api::CCMenuController#stack` resolves `Stack B` via `Stack.from_param!(params[:stack_id])` (bypassing the `stacks` scoping), and the response returns `Stack B`'s deploy/rollback status — despite the token only being authorized to read `Stack A`. [5](#0-4)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
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
