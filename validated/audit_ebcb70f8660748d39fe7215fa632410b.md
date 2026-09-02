### Title
CCMenuController stack lookup bypasses the ApiClient's `stack_id` scope binding, allowing a stack-scoped CCMenu token to read any other stack's deploy status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` scopes an `ApiClient` to a single stack via `current_api_client.stack_id`, enforced through the shared `stacks`/`stack` helpers. `Shipit::Api::CCMenuController` overrides `stack` to resolve directly from the request parameter instead of from the scoped `stacks` relation, breaking the binding "stack a token authorizes == stack it touches," analogous to the `relist` bug where a field acted upon was never checked against the state that should have gated it.

### Finding Description
`BaseController` defines the intended authorization binding: a stack-scoped `ApiClient` may only touch the stack it was created for. [1](#0-0) 

`require_permission!` only checks the coarse `operation:scope` string (e.g. `read:stack`), never the specific stack identity: [2](#0-1) 

`CCMenuController` declares `require_permission :read, :stack`, but overrides `stack` to bypass the scoped `stacks` helper entirely, resolving directly from `params[:stack_id]` via `Stack.from_param!`: [3](#0-2) 

Compare this with the sibling controller `Shipit::Api::StacksController`, which correctly resolves through the scoped `stacks` relation: [4](#0-3) 

CCMenu tokens are commonly created scoped to a single stack — e.g. `CCMenuUrlController#client` builds an `ApiClient` with `read:stack` permission for a specific stack and hands its `authentication_token` to the requester as a URL query parameter: [5](#0-4) 

The binding that should hold is: `token.stack_id == stack_touched`. Before the request, the token is scoped only to the stack it was minted for (`current_api_client.stack_id? → Stack.where(id: current_api_client.stack_id)`, base_controller.rb:75). After `CCMenuController#show` runs, the actual stack touched is whatever `params[:stack_id]` says, unconstrained by `current_api_client.stack_id` — the equality is broken, exactly like `relist` acting on a listing without checking the `_isLiquidation` state that should have gated the tax/refund flow.

### Impact Explanation
Anyone holding a legitimately-issued, stack-scoped CCMenu token (e.g. shared in a CI dashboard, chat integration, or public status page URL) can substitute an arbitrary `stack_id` in the request to read the latest deploy/rollback status of any other stack in the installation, including stacks they were never granted `read:stack` access to. This is an unauthenticated read of stack state/deploy output crossing an authorization boundary that the token system is supposed to enforce, matching the High-impact bucket "unauthenticated read of stack state, task streams or deploy output."

### Likelihood Explanation
Any holder of a valid, narrowly-scoped CCMenu token (an unprivileged, non-admin credential intentionally distributed for read-only status polling) can exploit this with a single parameter substitution — no additional secrets, no GitHub credentials, and no elevated permissions are required beyond possessing one such token.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the scoped `stacks` helper (as `StacksController` and other API controllers do) instead of `Stack.from_param!(params[:stack_id])` directly, so a stack-scoped `ApiClient` can never resolve a stack outside its `stack_id`.

### Proof of Concept
1. Admin creates a CCMenu URL for Stack A via `CCMenuUrlController#fetch`; this mints an `ApiClient` scoped to Stack A with `read:stack` permission and returns a URL containing `token=<A-scoped-token>`. [5](#0-4) 
2. An attacker who obtains this token (it is designed to be shared, e.g., pasted into CI dashboards) sends `GET /api/stacks/<OwnerB>/<RepoB>/<envB>/ccmenu.xml?token=<A-scoped-token>`.
3. `CCMenuController#authenticate_api_client` authenticates the token successfully (it is valid, just scoped to Stack A): [6](#0-5) 
4. `require_permission :read, :stack` passes because the token does have `read:stack` permission (base_controller.rb:82-84), and `stack` resolves Stack B directly from the URL param, ignoring `current_api_client.stack_id`: [7](#0-6) 
5. The response discloses Stack B's latest deploy/rollback status, even though the token was only ever authorized for Stack A.

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-31)
```ruby
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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-18)
```ruby
  class CCMenuUrlController < ShipitController
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
