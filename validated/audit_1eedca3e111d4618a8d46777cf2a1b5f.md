### Title
Api::CCMenuController bypasses ApiClient stack scoping, letting a stack-scoped token read the CI state of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` restricts an `ApiClient` to the single `Stack` it was issued for via `#stacks`/`#stack`, but `Shipit::Api::CCMenuController` overrides `#stack` with an unscoped lookup, breaking the binding "a stack a token authorises versus a stack it touches."

### Finding Description
`Api::BaseController` defines the authorization-scoping helpers used by every API controller: [1](#0-0) 

`stacks` restricts the queryable set of stacks to `current_api_client.stack_id` when the `ApiClient` record has one set, and `stack` resolves `params[:stack_id]` against that restricted scope. This is the mechanism that enforces "a stack-scoped token may only touch its own stack" — exactly the trust binding described.

`Api::CCMenuController`, however, overrides `stack` with a call directly against the unscoped `Stack` model, completely bypassing the `current_api_client.stack_id` restriction: [2](#0-1) 

The controller only enforces `require_permission :read, :stack` (a permission-string check on `ApiClient#permissions`, unrelated to which specific stack), via `ApiClient#check_permissions!`: [3](#0-2) 

Fixtures confirm the intended scoping model: `here_come_the_walrus` is an `ApiClient` bound to a single `stack: shipit` with only `read:stack` permission, and other tests explicitly assert this token "will only see that one stack" when hitting the scoped `stacks`/`stack` helpers (e.g. `StacksController#index`): [4](#0-3) [5](#0-4) 

The `CCMenuController` test suite exercises the endpoint with an unscoped client and never tests scoping, so the bypass is not caught: [6](#0-5) 

Before the attacker's request: a token scoped to `stack_id = S1` is expected to only authorize reads of `S1`. After the request: because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` instead of `stacks.from_param!(...)`, the same token can be used with `params[:stack_id] = S2` (any other stack in the installation) and successfully render that stack's CCTray XML.

### Impact Explanation
This is an authorization-scoping bypass: a narrowly-scoped credential (an `ApiClient` deliberately restricted to one stack for least-privilege reasons) can be used to read deploy/build status (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl` — see the `show` action) of every other stack in the Shipit instance, including stacks belonging to different repositories/teams that the token owner should have no visibility into. This matches the "unauthorized/unintended read of stack state" escalation category — the token escapes its intended `Shipit.github_teams`/stack-level authorization boundary.

### Likelihood Explanation
Any holder of a legitimately-issued, stack-scoped `ApiClient` token (a routine, low-privilege credential meant for CI status badges) can trigger this simply by changing the `stack_id` path segment in the request URL — no additional secrets, sessions, or write access are required. This is straightforward to exploit for any party that has been issued a scoped read-only token for one project.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` and rely on the inherited, properly scoped `Api::BaseController#stack` (`stacks.from_param!(params[:stack_id])`) so that stack-scoped `ApiClient`s cannot resolve stacks outside `current_api_client.stack_id`.

### Proof of Concept
1. Create an `ApiClient` with `stack: S1`, permissions `['read:stack']` (as in fixture `here_come_the_walrus`), and obtain its `authentication_token`.
2. Request `GET /api/S2.xml` (CCMenu route) for a different stack `S2`, authenticating with `token=<S1-scoped token>` as query param (as supported by `CCMenuController#authenticate_api_client`):
   - `stack` in `Api::BaseController` would reject this because `stacks` is limited to `Stack.where(id: S1)`.
   - `CCMenuController#stack` instead calls `Stack.from_param!(params[:stack_id])`, which finds `S2` unconditionally.
3. The response renders `S2`'s CCTray project XML (`name`, `lastBuildStatus`, etc.), even though the token was only ever authorized for `S1`.

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

**File:** test/controllers/api/ccmenu_controller_test.rb (L1-31)
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

      test "can authenticate with query string token" do
        request.headers['Authorization'] = 'bleh'
        get :show, params: { stack_id: @stack.to_param, token: @client.authentication_token }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```
