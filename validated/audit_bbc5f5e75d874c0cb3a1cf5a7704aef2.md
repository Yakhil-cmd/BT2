### Title
CCMenuController resolves stacks without enforcing the ApiClient's `stack_id` scope, allowing a stack-scoped token to read the state of any stack - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
The `ccmenu` API endpoint looks up the target `Stack` directly from the request parameter instead of going through the scoped lookup used everywhere else in the API. This breaks the binding "the stack a token authorises" (`ApiClient#stack_id`) versus "the stack it touches" (`params[:stack_id]`), letting any holder of a stack-scoped CI/CCMenu token read build/deploy state for stacks that token was never granted access to.

### Finding Description
`Shipit::Api::BaseController` scopes stack lookups to the calling `ApiClient`'s authorized stack: [1](#0-0) 
```
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This is the binding: an `ApiClient` can be created scoped to a single `stack_id` (as `CCMenuUrlController` does), and `PERMISSIONS` such as `read:stack` are checked with `ApiClient#check_permissions!`, which only checks the permission *name*, not the stack scope: [2](#0-1) 

The scope enforcement therefore depends entirely on `stacks`/`stack` filtering by `current_api_client.stack_id`. `CCMenuController` overrides `stack` and bypasses this scoping entirely, looking the stack up unconditionally from the raw request parameter: [3](#0-2) 
```
private

def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
```
The `require_permission :read, :stack` before_action still passes (the client legitimately has `read:stack`), but the actual object acted on (`params[:stack_id]`) is never checked against `current_api_client.stack_id`, which is exactly how such tokens are meant to be constrained: [4](#0-3) 

`CCMenuUrlController` is the normal issuer of these tokens and explicitly creates them scoped to one stack with only `read:stack`: [5](#0-4) 

The equality that should hold is: `current_api_client.stack_id == stack.id` (when the client is stack-scoped). `CCMenuController#stack` violates this by resolving `stack` purely from the attacker-supplied `params[:stack_id]`, independent of `current_api_client.stack_id`.

### Impact Explanation
This matches "High - unauthenticated read of stack state, task streams or deploy output" from the accepted impact list: `Api::CCMenuController#show` renders `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl` (a permalink into the deploy/task, which further discloses build/deploy detail) for any stack, not just the one the token was scoped to: [6](#0-5) 
A token holder who is only supposed to see one stack's CI status (e.g., a token shared with a third-party CI dashboard, or a token embedded in a public CCMenu URL) can enumerate and read the deploy state of every other stack in the Shipit instance.

### Likelihood Explanation
Any legitimate holder of a CCMenu-scoped token (created for stack A) can trivially substitute a different `stack_id` in the query string — no additional privilege, secret, or cryptographic bypass is required, since the token's basic-auth/query-string authentication (`ApiClient.authenticate(params[:token])`) succeeds as designed; only the per-stack scoping check is missing. This requires no privileged account, no session, and no signature forgery, satisfying the unprivileged-attacker requirement.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped lookup from the base controller (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the `ApiClient#stack_id` scope is enforced identically to the rest of the API.

### Proof of Concept
1. A user obtains a CCMenu URL for Stack A via `GET /stacks/A/ccmenu_url`, which creates (or reuses) an `ApiClient` scoped to `stack_id: A` with permission `read:stack` and returns a URL containing `?token=<tokenA>`. [7](#0-6) 
2. The attacker requests `GET /api/stacks/B/ccmenu.xml?token=<tokenA>` for an unrelated Stack B they have no access to.
3. `authenticate_api_client` in `CCMenuController` authenticates `tokenA` successfully; `require_permission :read, :stack` passes because `tokenA` has `read:stack`; `stack` resolves to Stack B via unscoped `Stack.from_param!`. [8](#0-7) 
4. The response discloses Stack B's `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `webUrl`, none of which `tokenA` was authorized to view.

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
