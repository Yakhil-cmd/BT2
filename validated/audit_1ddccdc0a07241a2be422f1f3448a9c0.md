### Title
Stack-scoped API token bypasses its `stack_id` binding, allowing unauthorized read of any stack's build/deploy status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup method from `BaseController` in a way that skips the token's stack scoping, letting a token that is authorized only for one specific stack read the CCTray/CCMenu build status of any other stack in the installation.

### Finding Description
`Shipit::Api::BaseController` defines the trust binding "a stack a token authorizes vs. a stack it touches": `stacks` restricts the queryable stacks to `current_api_client.stack_id` when the `ApiClient` is scoped, and `stack` resolves the requested `:stack_id` param only within that scoped collection: [1](#0-0) 

`CCMenuController` requires only the coarse `read:stack` permission and re-defines `stack` to bypass the scoped `stacks` collection entirely, resolving directly against the global `Stack` table: [2](#0-1) 

`ApiClient#check_permissions!` only validates the coarse `operation:scope` permission string (e.g. `read:stack`); it has no notion of which specific stack the token is bound to: [3](#0-2) 

Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly instead of `stacks.from_param!(params[:stack_id])`, the per-token `stack_id` restriction defined in `BaseController#stacks` (used by every other API controller such as `LocksController`, `TasksController`, `OutputsController`, `MergeRequestsController`) is never enforced here.

The fixture `here_come_the_walrus` demonstrates the intended model: a token created with `stack: shipit` and only `read:stack` permission is meant to be confined to that single stack: [4](#0-3) 

`Stacks::Api::StacksController` (and its tests) confirm this scoping contract is honored elsewhere in the API — a scoped client "will only see that one stack": [5](#0-4) 

But `CCMenuController`'s existing test suite only ever exercises the client's own bound stack (`@stack = shipit_stacks(:shipit)`), and never verifies that a stack-scoped token cannot access a different stack's CCMenu: [6](#0-5) 

This equality that should hold — `token.authorized_stacks == token.touched_stacks` — is broken specifically in this endpoint: a token authorized only for stack A can touch (read) stack B.

### Impact Explanation
This is an unauthenticated-scope escalation: a credential deliberately restricted by its issuer to a single stack (via `ApiClient#stack_id`) can be used to read build/deploy status (last build status, last build label, last build time, web URL) of **any** stack in the Shipit installation, including stacks the token holder should have no visibility into. This matches the "High" impact category of unauthorized read of stack state via a scope/authorization boundary bypass.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped API tokens (a documented and tested feature, `stack_id` on `ApiClient`) to third parties/teams for restricted access. Any holder of such a token can trivially enumerate other stacks by iterating `owner/repo/environment` parameters — no additional privilege, secret, or session is required beyond the token itself, which was only ever meant to unlock one stack.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to use the token-scoped `stacks` collection from `BaseController`, i.e. `stacks.from_param!(params[:stack_id])`, instead of `Stack.from_param!(params[:stack_id])`, so the per-token `stack_id` restriction is enforced consistently with every other API controller.

### Proof of Concept
1. Create/obtain an `ApiClient` scoped to `stack_id` = Stack A (e.g., analogous to the `here_come_the_walrus` fixture) with only `read:stack` permission.
2. As this token, request `GET /api/{other_owner}/{other_repo}/{other_environment}/ccmenu.xml?token=<token>` for Stack B, a stack the token is *not* scoped to.
3. Because `CCMenuController#stack` calls `Stack.from_param!` (unscoped) rather than `stacks.from_param!` (scoped), the request succeeds with `200 OK` and returns Stack B's `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, etc., even though the token was only authorized for Stack A — contrary to the behavior enforced identically in `LocksController`, `OutputsController`, `TasksController`, and the base `StacksController#index`/`#show`.

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

**File:** test/controllers/api/ccmenu_controller_test.rb (L1-24)
```ruby
# frozen_string_literal: true

require 'test_helper'

module Shipit
  module Api
    class CCMenuControllerTest < ApiControllerTestCase
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
```
