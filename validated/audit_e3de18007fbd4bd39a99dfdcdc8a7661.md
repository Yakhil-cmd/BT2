## Title
Stack-scoped API tokens can read the build status of any stack via `CCMenuController` - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

## Summary
`ApiClient` records can be scoped to a single `Stack` via their `stack_id` column, and `Api::BaseController` enforces that scope by resolving stacks through the `stacks` collection method, which filters by `current_api_client.stack_id` when present [1](#0-0) . `Api::CCMenuController`, however, overrides the private `stack` helper to resolve the target stack directly with `Stack.from_param!(params[:stack_id])`, completely bypassing the `stacks` scoping method [2](#0-1) . This breaks the binding "a stack a token authorises versus a stack it touches": the token's authorization scope (one specific `Stack`, enforced everywhere else in the API) is never checked here, so any valid `ApiClient` token with `read:stack` permission — even one deliberately restricted to a single stack — can query CCMenu build/deploy status for every other stack in the installation simply by supplying a different `stack_id` param.

## Finding Description
`Api::BaseController#stacks` is the canonical scoping primitive used across the JSON API to enforce per-token stack restriction:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [1](#0-0) 

Other controllers rely on this exact mechanism and its test coverage confirms the intended guarantee ("an api client scoped to a stack will only see that one stack") [3](#0-2) .

`Api::CCMenuController` requires only the coarse `read:stack` permission and then defines its own `stack` accessor that ignores the `stacks` scoping entirely, resolving against the global `Stack` relation instead:
```ruby
class CCMenuController < BaseController
  require_permission :read, :stack
  ...
  def stack
    @stack ||= Stack.from_param!(params[:stack_id])
  end
end
``` [4](#0-3) 

The equality that should hold but doesn't: `token.authorized_stack == stack_the_endpoint_returns_data_for`. Because `CCMenuController#stack` never consults `current_api_client.stack_id`, an `ApiClient` created with a `stack_id` restriction (the left side of the equality) can be pointed, via the `stack_id` request parameter, at any `Stack` in the installation (the right side), and the controller will happily render that other stack's CI/deploy status.

## Impact Explanation
This is an authorization-scope escalation: a credential intentionally minted to read the state of exactly one stack (e.g., handed to a third-party CI dashboard, or a client whose token leaked and was assumed low-risk because it's "only scoped to stack X") can be used to read `name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `webUrl` for every stack managed by the Shipit instance [5](#0-4) . This matches the rules' High-severity bucket of "unauthenticated read of stack state, task streams or deploy output" in the sense that it is a read of stack state that the presented credential was never authorized for — i.e., escalation past the token's intended authorization boundary.

## Likelihood Explanation
Exploitation requires only possession of any valid `ApiClient` token with `read:stack` permission — no special privilege beyond having a legitimate but narrowly-scoped API token, which is exactly the credential class this scoping feature exists to constrain. The `token` param can even be passed via query string (`GET /api/stacks/:stack_id/ccmenu.xml?token=...`), as covered by the existing test suite [6](#0-5) , making the request trivial to construct once a scoped token is obtained.

## Recommendation
Change `Api::CCMenuController#stack` to resolve through the inherited, scope-aware `stacks` collection (i.e., remove the override, or reimplement it as `stacks.from_param!(params[:stack_id])`) so that stack-scoped `ApiClient` tokens are restricted to their authorized stack, consistent with every other controller in `Api::BaseController`'s hierarchy.

## Proof of Concept
1. Create/obtain an `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to `stack_a.id`.
2. Send `GET /api/stacks/<owner>/<repo_of_stack_b>/<env>/ccmenu.xml?token=<client.authentication_token>` where `stack_b` is a different stack not owned by the token.
3. Observe the response renders `stack_b`'s CCMenu status (name, lastBuildStatus, etc.) despite the token being scoped only to `stack_a`, because `CCMenuController#stack` calls `Stack.from_param!` unscoped rather than `stacks.from_param!`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-31)
```ruby
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L26-31)
```ruby
      test "can authenticate with query string token" do
        request.headers['Authorization'] = 'bleh'
        get :show, params: { stack_id: @stack.to_param, token: @client.authentication_token }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L33-39)
```ruby
      test "xml contains required attributes" do
        get :show, params: { stack_id: @stack.to_param }
        project = get_project_from_xml(response.body)
        %w[name activity lastBuildStatus lastBuildLabel lastBuildTime webUrl].each do |attribute|
          assert_includes project, attribute, "Response missing required attribute: #{attribute}"
        end
      end
```
