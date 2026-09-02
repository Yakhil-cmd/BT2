## Title
CCMenu API endpoint bypasses stack-scoped ApiClient authorization, allowing a token scoped to one stack to read any stack's status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` authenticates requests with a valid `ApiClient` token but resolves the target `stack` without going through the scope check that every other API controller relies on, letting a token that is authorized for one stack read CI/deploy data for any stack.

### Finding Description
`Shipit::Api::BaseController` defines the standard way controllers resolve the target stack, deliberately restricting it to the stack an `ApiClient` is scoped to: [1](#0-0) 

`ApiClient` supports an optional `stack` association precisely so a token can be limited to a single stack (`belongs_to :stack, optional: true`), and `check_permissions!` only checks the operation/scope pair (e.g. `read:stack`), never the specific stack id: [2](#0-1) 

The fixtures confirm this scoping is an intended, load-bearing security control (e.g. `here_come_the_walrus` is scoped to `stack: shipit` and other tests assert `"an api client scoped to a stack will only see that one stack"`): [3](#0-2) 

However, `CCMenuController` overrides `stack` to bypass the scoped `stacks` relation entirely and resolve any stack directly from the request parameter, while still authenticating via the generic token lookup: [4](#0-3) 

The binding that should hold is:
`current_api_client.stack_id (the stack the token authorizes) == stack (the stack the request touches)`

In `StacksController` and other `Api::BaseController` subclasses this equality is enforced through `stacks`/`stack`. In `CCMenuController` it is broken: `require_permission :read, :stack` only verifies the client has the `read:stack` permission string, and `stack` then does `Stack.from_param!(params[:stack_id])` — ignoring `current_api_client.stack_id` completely. Because `authenticate_api_client` is also overridden to accept the token via a `params[:token]` query parameter (the same signed id used for Basic Auth), any leaked or captured CCMenu-style token — including one deliberately scoped to a single stack via the standard `ApiClientsController` UI — can be replayed against `/api/*/ccmenu?token=...` with a different `stack_id` to read another stack's build/deploy status.

### Impact Explanation
This is an authorization boundary break equivalent to the reported bug class ("a stack a token authorises versus a stack it touches"). A token that a Shipit operator intentionally scoped to a single stack (e.g., to hand to an external CI status dashboard) can be used to read the deploy/build status of every other stack on the installation, an unauthenticated-relative-to-scope read of stack state and deploy output — matching the High-severity impact category "escalation into `Shipit.github_teams` authorization, unauthenticated read of stack state, task streams or deploy output."

### Likelihood Explanation
CCMenu tokens are specifically designed to be embedded in URLs handed to third-party CI aggregator tools (`CCMenuUrlController` generates such URLs with the token in the query string), which increases the chance of exposure/leakage through logs, browser history, or the aggregator tool itself. Once such a token is obtained, exploitation only requires changing `stack_id` in the request — no additional secrets or privileges are needed.

### Recommendation
Make `CCMenuController#stack` resolve through the scoped `stacks` relation from `Api::BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so a stack-scoped `ApiClient` cannot read data for a stack outside its assigned `stack_id`.

### Proof of Concept
1. As an authorized user, create an `ApiClient` scoped to `stack: A` with `permissions: ['read:stack']` (e.g. via the `ApiClientsController` UI), obtaining `token_A`.
2. Request `GET /api/A/ccmenu?token=token_A` — succeeds as expected, returns stack A's status.
3. Request `GET /api/B/ccmenu?token=token_A` for an unrelated stack B — `authenticate_api_client` succeeds (token is valid), `require_permission :read, :stack` passes (client has `read:stack`), and `stack` resolves stack B directly via `Stack.from_param!`, ignoring that `token_A.stack_id == A`. The response discloses stack B's deploy/build status even though `token_A` was never authorized for stack B.

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

**File:** app/models/shipit/api_client.rb (L7-45)
```ruby
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
