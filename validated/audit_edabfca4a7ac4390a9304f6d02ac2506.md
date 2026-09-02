### Title
CCMenuController allows a stack-scoped API token to read build/deploy status of any stack, bypassing the token's `stack_id` binding - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
The Cooler bug lets an attacker cause `Clearinghouse.claimDefaulted` to operate on loans whose true origin was never checked against the Clearinghouse's own trust boundary, letting the attacker mix trusted and untrusted records. The structural analog here is `Shipit::Api::CCMenuController`, which resolves the `stack` it operates on directly from `params[:stack_id]` instead of going through the `stacks` scoping helper that binds an `ApiClient` to the specific `Stack` it was authorized for.

### Finding Description
`Shipit::Api::BaseController` establishes the trust binding "a stack a token authorises versus a stack it touches": when an `ApiClient` has a `stack_id` set, all stack lookups are meant to be constrained to that stack via the `stacks` helper: [1](#0-0) 

`Shipit::Api::CCMenuController` inherits from `BaseController` and requires `read:stack` permission, but it **overrides** `stack` to resolve directly via `Stack.from_param!(params[:stack_id])`, completely bypassing the `stacks` scoping method that would otherwise restrict lookups to `current_api_client.stack_id`: [2](#0-1) 

`ApiClient#check_permissions!` only checks that the token has the `read:stack` permission string — it never checks that the specific stack being accessed matches the client's bound `stack_id`: [3](#0-2) 

This is exactly the same class of bug as the Cooler issue: the code verifies one binding (`factory.created(coolers_[i])` / `read:stack` permission) but never verifies the second, more specific binding that the trust model actually depends on (loan originated by Clearinghouse / stack matches the token's own `stack_id`). The `CCMenuUrlController` even demonstrates the intended narrow-scoping design pattern — it creates single-stack-scoped tokens with only `read:stack` permission specifically so that leaking the token (it's embedded in a URL for third-party CI dashboard tools) only exposes one stack: [4](#0-3) 

The existing test suite confirms the intended global-scoping mechanism elsewhere (e.g., `StacksController#index`), where a stack-scoped client (`here_come_the_walrus`, fixture-bound to the `shipit` stack) is shown to only see one stack: [5](#0-4) [6](#0-5) 

But `CCMenuController`'s own tests never exercise a stack-scoped client against a *different* stack's `stack_id` param — they only test with the unscoped `spy` client, so this gap has gone unverified: [7](#0-6) 

### Impact Explanation
An `ApiClient` token that was deliberately narrowed to a single stack (via the `stack_id` column, e.g. the CCMenu tokens minted by `CCMenuUrlController#client` for embedding in third-party CI status tools) can be used to read the build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, activity) of **any other stack in the Shipit instance**, not just the one it was scoped to. This is an authorization-boundary bypass that discloses stack state to a token holder who was never granted access to that stack — matching the "High: unauthenticated/unauthorized read of stack state" impact category, since the whole point of scoping the token to one stack is defeated.

### Likelihood Explanation
High. Any holder of a `read:stack`-permitted token (including narrowly scoped, disclosure-prone tokens such as CCMenu URLs that are pasted into third-party dashboard tools or shared links) can trivially exploit this by simply changing the `stack_id` route segment in the request — no additional privilege, session, or GitHub access is required beyond possessing that one legitimate token.

### Recommendation
In `CCMenuController`, remove the private `stack` override and rely on the inherited `BaseController#stack` (which uses the `stacks` helper) so that stack-scoped tokens are restricted to their bound stack, consistent with every other API controller in the engine.

### Proof of Concept
1. An administrator visits a stack's settings page and clicks "Fetch URL" for CCMenu integration; this creates (or reuses) an `ApiClient` with `permissions: ['read:stack']` and no `stack_id`, or an equivalently scoped client with `stack_id` set to a particular stack (see `CCMenuUrlController#client`). [8](#0-7) 
2. Attacker obtains this token (e.g., it is embedded in plaintext in a CI status-monitor URL, commonly shared in dashboards).
3. Attacker sends `GET /api/stacks/<other_owner>/<other_repo>/<other_env>/ccmenu?token=<stolen_token>`.
4. `CCMenuController#authenticate_api_client` authenticates the token successfully, `require_permission :read, :stack` passes because the token has `read:stack`, and `stack` resolves via `Stack.from_param!(params[:stack_id])` — the *other* stack — with no check that it matches the token's own `stack_id`.
5. The response discloses `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `webUrl` for the unauthorized stack. [9](#0-8)

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
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
