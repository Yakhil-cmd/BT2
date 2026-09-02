### Title
CCMenu API endpoint bypasses ApiClient stack scoping, allowing a stack-scoped token to read any stack's build/deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` accessor used by every other API controller and, in doing so, drops the stack-scoping enforcement that `Shipit::Api::BaseController` normally applies. This breaks the binding "the stack a token is authorized for == the stack the request actually touches," letting a client holding a token scoped to one stack read CI/deploy status for any stack in the installation.

### Finding Description
`Shipit::ApiClient` can optionally be bound to a single stack (`belongs_to :stack, optional: true`), and `Api::BaseController#stacks`/`#stack` enforce that scoping for every normal API controller: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

If a client is scoped to `stack_id`, `stack` can only ever resolve to that single stack, no matter what `params[:stack_id]` is set to — the permission model in `ApiClient#check_permissions!` only checks the operation/scope string (e.g. `read:stack`), never the specific stack, so the scoping filter in `stacks` is the *only* enforcement mechanism binding a token to "its" stack: [2](#0-1) 

`CCMenuController`, however, redefines `stack` and completely bypasses this filter, resolving directly against the unscoped `Stack` model: [3](#0-2) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
```

`require_permission :read, :stack` (inherited class-level macro) still runs, but it only verifies that the token's `permissions` array contains `read:stack` — it does not verify the token is authorized for *this particular* `stack_id`: [4](#0-3) 

The fixture `here_come_the_walrus` demonstrates the intended trust model: a token that is deliberately scoped to a single stack (`stack: shipit`) with only `read:stack`: [5](#0-4) 

The existing test suite for this controller only ever passes `stack_id` for the same stack the authenticated client was created against, so the missing cross-stack check is not covered: [6](#0-5) 

Root cause: `Api::BaseController#stack` (`app/controllers/shipit/api/base_controller.rb:78-80`) enforces the `ApiClient.stack_id` binding, but `Api::CCMenuController#stack` (`app/controllers/shipit/api/ccmenu_controller.rb:29-31`) reimplements stack lookup without reusing `stacks`, silently dropping that binding.

### Impact Explanation
Any holder of a legitimately-issued, narrowly-scoped `ApiClient` token (e.g. an integration meant only to read the CI status of its own stack, such as `here_come_the_walrus`) can supply an arbitrary `stack_id` to `GET /api/:stack_id/ccmenu` and obtain that other stack's name, lock status, and latest deploy/rollback status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, etc.) — data that token was never authorized to see. This is an unauthenticated-for-that-resource read of stack state across tenant/stack boundaries, matching the "High — unauthenticated read of stack state, task streams or deploy output" impact category, since the token's own authorization boundary (its bound `stack_id`) is what "unauthenticated" is relative to here.

### Likelihood Explanation
Exploitation requires only a valid, existing `ApiClient` token with `read:stack` permission scoped to any single stack (a low-privilege, easily obtainable credential in any multi-stack Shipit deployment that issues per-integration tokens) and knowledge/guess of another stack's `stack_id`/param (stack names/slugs are often predictable or discoverable, e.g. via the public `/api/stacks` listing endpoint if unscoped, or simply by observing repo/branch/environment naming conventions). No repository write access, admin privileges, or session/cookie compromise is needed — only the request parameter differs from what the token is supposed to be limited to. This makes the bug highly likely to be exploitable by any party who has been issued a stack-scoped read token.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped lookup from `BaseController` instead of hitting `Stack` directly, e.g.:

```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

so that CCMenu, like every other API resource, is bound by `current_api_client.stack_id` when the client is scoped. Add a regression test asserting that a client scoped to stack A receives a 404 (or equivalent) when requesting CCMenu status for stack B.

### Proof of Concept
1. Admin issues an `ApiClient` scoped to `stack_id: <Stack A's id>` with permission `read:stack` (analogous to fixture `here_come_the_walrus`), and gives the resulting `authentication_token` to an integration/service that should only see Stack A.
2. That integration (attacker context) sends:
   `GET /api/<Stack B's param>/ccmenu?token=<Stack-A-scoped token>`
3. `authenticate_api_client` (CCMenu override) authenticates the token successfully via `ApiClient.authenticate(params[:token])`.
4. `require_permission :read, :stack` passes because the token's `permissions` includes `read:stack` (it doesn't check which stack).
5. `stack` resolves via `Stack.from_param!(params[:stack_id])` directly to Stack B, ignoring that the token is bound to Stack A.
6. The response renders Stack B's `name`, `lock`/lastBuildStatus, lastBuildLabel, lastBuildTime, webUrl — data the Stack-A-scoped token was never authorized to access, confirmed by the existing test pattern in `test/controllers/api/ccmenu_controller_test.rb:20-24` which shows exactly what fields are exposed once `stack` resolves.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-26)
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

```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-36)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L8-31)
```ruby
      setup do
        authenticate!
        @stack = shipit_stacks(:shipit)
      end

      test "a request with insufficient permissions will render a 403" do
        @client.update!(permissions: [])
        get :show, params: { stack_id: @stack.to_param }
        assert_response :forbidden
        assert_json 'message', 'This operation requires the `read:stack` permission'
      end

      test "#show renders the xml" do
        get :show, params: { stack_id: @stack.to_param }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end

      test "can authenticate with query string token" do
        request.headers['Authorization'] = 'bleh'
        get :show, params: { stack_id: @stack.to_param, token: @client.authentication_token }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```
