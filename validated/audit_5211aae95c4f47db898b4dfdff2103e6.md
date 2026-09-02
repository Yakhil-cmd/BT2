### Title
CCMenu API endpoint bypasses ApiClient stack scoping, letting a stack-scoped token read any stack's deploy state - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The bug class in the external report is a value used to authorize/settle a critical action being computed from a source that is not the one that was actually verified — the LP burn is priced from a manipulable spot reserve instead of a TWAP-protected value. The reachable analog in this engine is `Api::CCMenuController`, which authenticates an `ApiClient` token but then resolves the target `Stack` from a raw, unchecked parameter instead of from the same scope that was used to authorize the token, breaking the binding "stack a token authorises == stack a token touches."

### Finding Description
`Api::BaseController` defines the safe pattern: any endpoint that needs a `Stack` should resolve it through `stacks`, which is scoped to the authenticated `ApiClient`'s `stack_id` when the client is restricted to one stack: [1](#0-0) 

Every other API controller (e.g. `Api::StacksController`) uses this scoped `stacks.from_param!` helper: [2](#0-1) 

`Api::CCMenuController`, however, overrides `stack` to resolve directly against the global `Stack` relation, ignoring the client's `stack_id` scope entirely, while still enforcing only the coarse `read:stack` permission check: [3](#0-2) 

Authentication in this controller is also independent of `BaseController#authenticate_api_client`: it authenticates purely off `params[:token]` via `ApiClient.authenticate`, then resolves `params[:stack_id]` unscoped: [4](#0-3) 

`ApiClient#check_permissions!` only checks that the `"read:stack"` string is present in the client's `permissions` array — it never checks whether the requested stack matches `stack_id`: [5](#0-4) 

The stack-scope enforcement (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`) exists specifically so that a token created for one stack (e.g. `here_come_the_walrus`, scoped to `shipit`) cannot enumerate or read other stacks: [6](#0-5) 

Because `CCMenuController#stack` never routes through `stacks`, a token that is scoped to Stack A but carries `read:stack` permission can be replayed with an arbitrary `params[:stack_id]` for Stack B and will successfully render Stack B's CCMenu output — the authorization binding "token authorises stack A" is broken by "controller touches whatever stack_id is supplied."

### Impact Explanation
This escalates a stack-scoped `ApiClient` token into unauthenticated (unauthorized) read of another stack's deploy state — `lastBuildStatus`, `activity` (building/sleeping), `lastBuildTime`, `lastBuildLabel` (deploy id), and `webUrl` — for any stack in the installation, not just the one the token was issued for: [7](#0-6) 
This matches the "High" impact bar defined by the rules: escalation into authorization scope / unauthenticated read of stack state or deploy output.

### Likelihood Explanation
Any holder of a legitimate, narrowly-scoped `ApiClient` token (the normal, unprivileged credential this engine issues to CI/monitoring integrations) can trigger this by simply changing the `stack_id` query parameter on the CCMenu endpoint — no additional privilege, secret, or session is required beyond the token they already legitimately hold for their own stack.

### Recommendation
Route `Api::CCMenuController#stack` through the same scoped `stacks` helper used elsewhere (`stacks.from_param!(params[:stack_id])`) so the resolved stack is always constrained by `current_api_client.stack_id` when the client is stack-scoped, matching the pattern already enforced in `Api::BaseController` and `Api::StacksController`.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_id: <shipit_stack.id>` with only the `read:stack` permission (this mirrors the `here_come_the_walrus` fixture) and obtain its `authentication_token`.
2. Call `GET /api/stacks/<any_other_stack_id>/ccmenu.xml?token=<token>` (per `app/controllers/shipit/api/ccmenu_controller.rb` route/authentication flow, using `params[:token]` and `params[:stack_id]`).
3. Observe that `Stack.from_param!(params[:stack_id])` resolves the arbitrary other stack (not the client's scoped stack), and the response renders that other stack's live deploy status/build label/web URL, even though the token's `stack_id` scope should have restricted visibility to only its own stack.

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L86-89)
```ruby

      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-37)
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

**File:** app/views/shipit/ccmenu/project.xml.builder (L1-16)
```text
# frozen_string_literal: true

# Derived from http://timnew.me/blog/2013/04/07/multiple-project-summary-reporting-standard-cctray-xml-feed/
status_map = { 'backlogged' => 'failure', 'locked' => 'failure' }
xml.instruct!
xml.Projects do
  xml.Project(
    '',
    name: stack.to_param,
    lastBuildStatus: status_map.fetch(stack.merge_status, stack.merge_status).capitalize,
    activity: deploy.running? ? 'Building' : 'Sleeping',
    lastBuildTime: deploy.ended_at || deploy.started_at || deploy.created_at,
    lastBuildLabel: deploy.id,
    webUrl: stack_url(stack)
  )
end
```
