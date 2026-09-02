### Title
Stack-scoped `ApiClient` tokens can read the CI status of any stack via `CCMenuController` bypassing stack scoping - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the inherited `stack` resolver with a version that ignores the `ApiClient`'s stack scope, so a token that is only authorised to read a single stack can be used to read the CI/deploy status of *every* stack in the Shipit instance simply by changing `stack_id` in the request.

### Finding Description
`Shipit::Api::BaseController` implements the intended trust binding between an `ApiClient` and the stack(s) it may operate on: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is scoped, and every controller is expected to resolve the requested `params[:stack_id]` through that scoped relation via `stacks.from_param!`.

`ApiClient` explicitly supports this per-stack binding (`belongs_to :stack, optional: true`), and `check_permissions!` only checks operation/scope, not which stack the operation targets — the stack restriction is enforced entirely by the `stacks`/`stack` helper in `BaseController`: [2](#0-1) 

`CCMenuController`, however, defines its own `stack` method that never goes through the scoped `stacks` relation — it resolves directly against the full `Stack` table using only the request parameter: [3](#0-2) 

The declared permission requirement is only `read_permission :read, :stack` (checked via `current_api_client.check_permissions!('read', 'stack')`), which never verifies which specific stack the token was bound to. So the equality that should hold — `stack the token authorises == stack the request touches` — is broken: the token authorises exactly the stack referenced by `current_api_client.stack_id`, but `CCMenuController#show` touches whatever stack the caller names in `params[:stack_id]`.

This is exactly analogous to the referenced report's root cause: a value used in one accounting/authorization step (`totalFee` subtracted from the burn but not from `poolTotalPeUSDCirculation`) is dropped from a later step that should have respected it. Here, the stack binding is enforced in `BaseController#stack`/`#stacks` but silently dropped in `CCMenuController#stack`.

### Impact Explanation
This lets the holder of a narrowly-scoped, low-privilege `read:stack` token (the kind an operator would hand out to embed a single stack's CI widget in an external tool/dashboard — exactly what `CCMenuUrlController#fetch` is designed to generate) enumerate `stack_id` values and pull the CCMenu XML (build/deploy status, last build label, running/locked state, lock reason, etc.) for any stack in the Shipit instance, including stacks the token was never meant to see. This matches the accepted High-impact category: "unauthenticated [by-scope] read of stack state" achieved by escalating a token's declared authorization scope.

### Likelihood Explanation
Likelihood is high for any deployment that issues scoped `read:stack` `ApiClient` tokens (a normal, documented, low-privilege usage pattern for CI dashboards/status badges). No repository write access, GitHub credentials, webhook secrets, or privileged accounts are needed — only possession of one legitimately-issued, narrowly-scoped token, plus the ability to change a URL parameter.

### Recommendation
Make `CCMenuController#stack` resolve through the inherited, scope-respecting `stacks` relation instead of querying `Stack` directly:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the binding enforced everywhere else in the API (`BaseController#stack`) between the `ApiClient`'s `stack_id` and the stack actually served.

### Proof of Concept
1. An operator creates (or the system creates, as in `CCMenuUrlController#fetch`) an `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to `Stack A`'s id, intended only to expose Stack A's CI badge.
2. Using that client's `authentication_token` as the `token` query parameter, the attacker requests:
   `GET /api/stacks/<STACK_B_PARAM>/ccmenu.xml?token=<TOKEN_SCOPED_TO_STACK_A>`
3. `CCMenuController#authenticate_api_client` authenticates the token fine (it's valid), `require_permission :read, :stack` passes (`read:stack` is present), and `CCMenuController#stack` resolves `Stack B` directly via `Stack.from_param!`, bypassing the `current_api_client.stack_id` check that `BaseController#stacks` would have enforced.
4. The response renders Stack B's build/deploy status XML even though the token was only ever authorised for Stack A — confirmed by the code paths in [4](#0-3)  versus the scoped resolver in [1](#0-0) .

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

**File:** app/models/shipit/api_client.rb (L4-21)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }
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
