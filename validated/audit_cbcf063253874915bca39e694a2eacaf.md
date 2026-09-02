### Title
Cross-stack authorization bypass in CCMenu API endpoint — token scoped to one stack can read any stack's status (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
Every other API controller in the engine resolves the target `Stack` through `BaseController#stack`, which restricts lookups to the set of stacks the authenticated `ApiClient` is scoped to. `Api::CCMenuController` overrides this resolution and calls `Stack.from_param!` directly, completely bypassing the per-client stack scope. This breaks the binding "the stack a token authorizes" vs "the stack it actually touches."

### Finding Description
`BaseController` defines the canonical, scope-respecting resolution: [1](#0-0) 

`current_api_client.stack_id?` limits the visible `Stack` collection to the one stack an `ApiClient` was created for (see `belongs_to :stack, optional: true` and `check_permissions!`, which only checks the coarse `operation:scope` string, never the specific stack): [2](#0-1) 

Every controller that needs a stack (`Api::StacksController`, `Api::LocksController`, `Api::TasksController`, etc.) relies on this scoped `stack`/`stacks` helper, so a client created with a specific `stack_id` and `read:stack` permission can only ever query that one stack.

`Api::CCMenuController`, however, redefines `stack` to bypass the scope entirely: [3](#0-2) 

It also overrides `authenticate_api_client` to allow authenticating via a `token` query-string parameter instead of Basic Auth, which is how CCMenu/CI-dashboard consumers are meant to use the URL: [4](#0-3) 

Because `stack` calls `Stack.from_param!(params[:stack_id])` instead of `stacks.from_param!(params[:stack_id])`, the `require_permission :read, :stack` before_action only verifies that the token carries the `read:stack` permission string — it never verifies that the requested `stack_id` matches the stack the token was scoped to: [5](#0-4) 

The existing tests only exercise the single-stack, non-adversarial case and never assert that a stack-scoped client is rejected when requesting a different `stack_id`, so this gap is untested: [6](#0-5) 

### Impact Explanation
An `ApiClient` that an administrator intentionally scopes to a single stack (via `stack_id` and `permissions: ['read:stack']`, exactly the kind of narrowly-scoped, embeddable token the CCMenu feature is designed to hand out to third-party CI dashboards) can be replayed with any other `stack_id` to read that other stack's build/lock/deploy status (`stack.merge_status`, `deploy.running?`, `deploy.ended_at`, `deploy.id`, `stack_url`) via `app/views/shipit/ccmenu/project.xml.builder`. This is an authorization-scope escalation: read access to deploy/task state of stacks the token holder was never granted access to, matching the "unauthorized read of stack state / deploy output" High-severity category.

### Likelihood Explanation
Likelihood is high for any deployment that uses per-stack scoped API clients (a documented, supported feature of `ApiClient`) together with the CCMenu integration. The token is passed as a plain query-string parameter designed for third-party consumption (CI dashboard widgets), increasing the chance of exposure/leakage, and no additional privilege or session is required to exploit it beyond possessing any valid `read:stack` token — the flaw is purely that the `stack_id` binding is never checked.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped resolution from `BaseController`:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the same `current_api_client.stack_id?` scoping enforced everywhere else in the API, so a stack-scoped token can only ever resolve to the stack it was issued for.

### Proof of Concept
1. Admin creates two stacks, `stack_a` and `stack_b`.
2. Admin (or the built-in `CCMenuUrlController#client` flow) creates/uses an `ApiClient` with `stack_id: stack_a.id` and `permissions: ['read:stack']`, and obtains its `authentication_token`.
3. Attacker (or the third party embedding the CCMenu widget) sends:
   `GET /api/stacks/:stack_b_id/ccmenu?token=<stack_a-scoped-token>`
4. `authenticate_api_client` succeeds (token is valid). `require_permission :read, :stack` passes because the client does have `read:stack` in its permissions list — it never checks which stack. `stack` resolves via `Stack.from_param!(params[:stack_id])` to `stack_b`, unrelated to the token's `stack_id`.
5. Response renders `stack_b`'s live build/lock/deploy status, which the token was never authorized to see.

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

**File:** app/models/shipit/api_client.rb (L4-46)
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

    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
      end

      def message_verifier
        @message_verifier ||= Shipit::SimpleMessageVerifier.new(Shipit.api_clients_secret)
      end
    end

    def authentication_token
      self.class.message_verifier.generate(id)
    end

    def check_permissions!(operation, scope)
      required_permission = "#{operation}:#{scope}"
      unless permissions.include?(required_permission)
        raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
      end

      true
    end
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
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
