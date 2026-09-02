### Title
`CCMenuController#stack` bypasses `current_api_client.stack_id` scoping via unscoped `Stack.from_param!` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`BaseController` scopes lookups of a stack by `current_api_client.stack_id` when the API client is bound to a single stack, via the `stacks`/`stack` helper methods. `CCMenuController` overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, discarding this scoping entirely.

### Finding Description
The intended binding is: `resolved_stack ∈ authorized_set`, where `authorized_set = current_api_client.stack_id? ? {Stack.find(current_api_client.stack_id)} : Stack.all` [1](#0-0) .

`BaseController` defines `stacks` to return `Stack.where(id: current_api_client.stack_id)` when the client is scoped to a single stack, and `stack` to resolve via `stacks.from_param!(params[:stack_id])`, which enforces the binding [1](#0-0) .

However, `CCMenuController` overrides `stack` with:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```
This calls `from_param!` on the bare `Stack` class (all stacks in the instance), not on the `stacks` scope, so `current_api_client.stack_id` is never consulted [2](#0-1) . The `require_permission :read, :stack` before_action only checks that the token has the `read:stack` permission string in `ApiClient#permissions`; it performs no ownership/scope check against the specific stack instance [3](#0-2) [4](#0-3) .

`ApiClient.authenticate` only verifies the signed token identifies a valid `ApiClient` row; it does not restrict which stack ids are resolvable in `show` [5](#0-4) .

Exploit flow: an attacker who legitimately obtains one API token scoped to `stack_id = A` (e.g., a token issued for their own repository's CCMenu integration) can call `GET /stacks/:stack_id_or_slug/cc_menu.xml?token=<token>` (via `authenticate_api_client` override that reads `params[:token]` directly, bypassing the need for Basic Auth [6](#0-5) ) with `stack_id` set to any other numeric id or guessed slug. Because `stack` never filters by `current_api_client.stack_id`, any existing stack in the whole Shipit instance will be resolved and rendered, exposing its name, lock state, and last build/deploy outcome via the rendered CCMenu XML [7](#0-6) .

The existing test suite only exercises the intended stack (`shipit_stacks(:shipit)`) and never checks that a stack-scoped token is denied access to a *different* stack id, so this gap has no regression coverage [8](#0-7) .

### Impact Explanation
Any holder of a single stack-scoped API token can enumerate and read the CI/CD status (name, lock state, last build outcome) of every stack across the entire Shipit instance, not just the stack their token was issued for. This is an unauthenticated-for-other-tenants read of stack state, matching the "High: escalation into unauthenticated read of stack state" impact category. It does not itself allow writes, deploys, or secret exfiltration, but it breaks the intended per-token tenant isolation and is fully repeatable by incrementing `stack_id` (or guessing slugs) for as long as the attacker holds any valid token.

### Likelihood Explanation
Preconditions: the attacker needs one valid, legitimately-issued token (`ApiClient.authentication_token`) scoped to a single stack (`stack_id` set) — a normal, low-privilege credential that Shipit issues for CCMenu integration purposes. No GitHub secrets, no `api_clients_secret`, no operator/maintainer role, and no knowledge of other stacks' owners is required — only sequential id guessing. Given stacks generally have small, sequential auto-increment ids, enumeration is cheap and fully automatable, making likelihood high once a single scoped token is obtained.

### Recommendation
Remove the `stack` override in `CCMenuController` (or change it to call `stacks.from_param!(params[:stack_id])` instead of `Stack.from_param!`) so it inherits/uses the properly scoped `stacks` method from `BaseController`, ensuring `current_api_client.stack_id` scoping is enforced identically to other API controllers.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a stack-scoped token cannot read other stacks via cc_menu" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "other", name: "repo"), branch: "main")

  @client.update!(stack_id: stack_a.id, permissions: ['read:stack'])

  get :show, params: { stack_id: stack_a.to_param, token: @client.authentication_token }
  assert_response :ok # expected: token's own stack is readable

  get :show, params: { stack_id: stack_b.to_param, token: @client.authentication_token }
  assert_response :not_found # BROKEN: currently returns :ok, disclosing stack_b's status
end
```
Assert on both sides of the binding: `resolved_stack.id` (currently can equal `stack_b.id`) must equal an element of `{current_api_client.stack_id}` (currently `stack_a.id` only) — the test demonstrates the equality is violated when `stack_id=stack_b.to_param` returns `200` instead of `404`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-6)
```ruby
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
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

**File:** app/models/shipit/api_client.rb (L24-27)
```ruby
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L1-63)
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

      test "xml contains required attributes" do
        get :show, params: { stack_id: @stack.to_param }
        project = get_project_from_xml(response.body)
        %w[name activity lastBuildStatus lastBuildLabel lastBuildTime webUrl].each do |attribute|
          assert_includes project, attribute, "Response missing required attribute: #{attribute}"
        end
      end

      test "locked stacks show as failed" do
        @stack.lock('test', @user)
        get :show, params: { stack_id: @stack.to_param }
        assert_payload 'lastBuildStatus', 'Failure'
      end

      test "stacks with no deploys render correctly" do
        stack = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: 'main')
        get :show, params: { stack_id: stack.to_param }
        assert_payload 'lastBuildStatus', 'Success'
      end

      private

      def get_project_from_xml(xml)
        Hash.from_xml(xml)['Projects']['Project']
      end

      def assert_payload(key, value)
        @project ||= get_project_from_xml(response.body)
        assert_equal(value, @project[key])
      end
    end
```
