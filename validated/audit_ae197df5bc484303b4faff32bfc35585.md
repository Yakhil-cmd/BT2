### Title
API-Scoped Token Bypasses Stack Authorization in `CCMenuController#stack` - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` accessor that `Shipit::Api::BaseController` otherwise uses to bind a request to a stack the authenticated `ApiClient` is actually authorized for. The override resolves the stack unscoped, breaking the equality that should hold: *the stack a token authorizes == the stack the request touches*.

### Finding Description
`Shipit::Api::BaseController` scopes stack lookups to the stacks an `ApiClient` is permitted to see: [1](#0-0) 

`ApiClient` supports being scoped to a single stack via `stack_id`, and `check_permissions!` only validates that the client's `permissions` array includes the operation (e.g. `read:stack`) — it never checks which stack is being accessed: [2](#0-1) 

Authorization to a *specific* stack is therefore enforced entirely by the `stacks`/`stack` helper in `BaseController`, which filters `Stack.where(id: current_api_client.stack_id)` when the client is scoped. `Shipit::Api::CCMenuController`, however, redefines `stack` to bypass that filter entirely, resolving the target stack directly from the unscoped `Stack` class: [3](#0-2) 

It also overrides `authenticate_api_client` to accept the token via a query parameter (`params[:token]`) instead of HTTP Basic Auth, which is expected for CCTray-style clients, but this change does not restore the missing stack scoping: [4](#0-3) 

The `before_action` installed by `require_permission(:read, :stack)` only calls `current_api_client.check_permissions!(:read, :stack)`, which — as shown above — is a global permission list check, not a per-stack check: [5](#0-4) [6](#0-5) 

Consequently, an `ApiClient` record that was created with `stack_id` set (i.e., explicitly restricted by an administrator to a single stack, per the test `"an api client scoped to a stack will only see that one stack"`) still has global `read:stack` permission and can supply any other stack's `stack_id` in the `/stacks/*stack_id/ccmenu` URL to fetch that other stack's CCMenu status — a stack it was never authorized to see.

### Impact Explanation
This breaks the "stack a token authorizes" vs. "stack it touches" binding described in the analog rules. A caller holding only a stack-scoped `ApiClient` token (not a global one) can use the `ccmenu` endpoint to read deploy/build status (`deploys_and_rollbacks.last`, its id, running state, and end time as rendered in `shipit/ccmenu/project`) for any stack in the Shipit instance, not just the one it was scoped to. This is an unauthenticated-for-that-resource / unauthorized read of stack state across stack boundaries, matching the High-severity category "escalation into `Shipit.github_teams` authorization ... or unauthenticated read of stack state, task streams or deploy output."

### Likelihood Explanation
Any deployment that issues stack-scoped `ApiClient` tokens (a supported and documented feature — see the `stack_id` column and the `"an api client scoped to a stack will only see that one stack"` test) is affected the moment that token is used against the `ccmenu` endpoint. No privileged access beyond possessing one's own legitimately-issued, narrowly-scoped API token is required — the whole point of scoping the token was to prevent it from being used outside its own stack, and this code path defeats that restriction directly.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController` (or reimplement it using the scoped `stacks.from_param!(params[:stack_id])` helper from `BaseController`) so that CCMenu stack resolution respects `current_api_client.stack_id` scoping, consistent with every other API controller.

### Proof of Concept
1. As an administrator, create an `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to Stack A's id (a stack-scoped token), and note its `authentication_token`.
2. As the holder of that token, issue: `GET /stacks/<StackB-owner>/<StackB-repo>/<StackB-env>/ccmenu?token=<token>` where Stack B is a different stack that the token was never scoped to.
3. Observe that `Shipit::Api::CCMenuController#stack` resolves Stack B via unscoped `Stack.from_param!`, and `require_permission :read, :stack` only checks the client's global permission list — the request succeeds and Stack B's deploy status is returned, even though the token is scoped to Stack A only. [7](#0-6)

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L18-22)
```ruby
      class << self
        def require_permission(operation, scope, options = {})
          before_action(options) { require_permission!(operation, scope) }
        end
      end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-39)
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
  end
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
