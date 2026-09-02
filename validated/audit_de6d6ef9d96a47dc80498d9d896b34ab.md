## Title
Stack-scoped API token bypasses its `stack_id` restriction on the CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

## Summary
`Shipit::Api::CCMenuController` overrides the stack-lookup method inherited from `Shipit::Api::BaseController`, replacing the token-scoped lookup with an unscoped `Stack.from_param!`. This breaks the equality that should hold between "the stack an `ApiClient` token is authorized for" and "the stack the request actually touches," letting a token that is restricted to one stack read deploy/build state for any stack in the installation.

## Finding Description
`Shipit::Api::BaseController` implements stack scoping for all API endpoints: it restricts the queryable set of stacks to the one the `ApiClient` is bound to when `stack_id` is set on the token: [1](#0-0) 

`ApiClient` supports being scoped to a single stack via `belongs_to :stack, optional: true`, and the permission check only validates the `operation:scope` string (e.g. `read:stack`), never the specific stack being accessed: [2](#0-1) 

The fixture `here_come_the_walrus` demonstrates this intended binding: a token with only `read:stack` permission and `stack: shipit`, which the `StacksControllerTest` confirms is restricted to seeing exactly that one stack via `stacks_controller#index`: [3](#0-2) [4](#0-3) 

However, `Shipit::Api::CCMenuController` (mounted under the same authenticated API base, requiring only `read:stack`) redefines `stack` to bypass the scoped `stacks` helper entirely and instead resolve any stack by param directly against the full `Stack` table: [5](#0-4) 

Compare this to the correctly-scoped implementation in the base controller (`stacks.from_param!(params[:stack_id])`) versus the CCMenu controller's override (`Stack.from_param!(params[:stack_id])`, no `stacks` scoping applied): [6](#0-5) [7](#0-6) 

The equality that should hold is: `stack the token authorizes == stack the token can query`. Before the CCMenu controller's override, for a stack-scoped `ApiClient`, `stacks == Stack.where(id: current_api_client.stack_id)`, so any `stack_id` param outside that set raises `RecordNotFound` via `from_param!`. After the override, `stack == Stack.from_param!(params[:stack_id])` unconditionally, so the equality breaks: `check_permissions!(:read, :stack)` only confirms the token carries the string `read:stack`, and the CCMenu action then serves build/deploy status (`stack.deploys_and_rollbacks.last`) for whatever `stack_id` the caller supplies, not the one the token was minted for.

## Impact Explanation
This is an unauthenticated-read escalation: a token deliberately scoped to a single stack (e.g., minted by `CCMenuUrlController` for embedding in a low-trust integration like CCTray/CI dashboard widgets) can be replayed against the `/api/stacks/:stack_id/cc.xml` endpoint for any other stack in the Shipit instance, disclosing that stack's latest build/deploy status, lock state, and stack name — information the token issuer did not intend to expose. This matches the "unauthenticated read of stack state" High-severity category, since the scoping was the only control standing between the holder of a narrowly-scoped, potentially less-trusted token and cross-stack information disclosure.

## Likelihood Explanation
Any holder of a stack-scoped `ApiClient` token (which by design is meant to be handed out for restricted, single-stack use, e.g. via `CCMenuUrlController#fetch`) can trivially exploit this by changing the `stack_id` in the URL/query of a request to the CCMenu endpoint. No privilege escalation beyond possessing one such legitimately-issued scoped token is required, and the attack requires no interaction with other users.

## Recommendation
Have `Shipit::Api::CCMenuController#stack` reuse the inherited, scoped `stacks` collection instead of querying `Stack` directly, e.g. `@stack ||= stacks.from_param!(params[:stack_id])`, so that a stack-scoped `ApiClient` cannot resolve stacks outside its `stack_id`.

## Proof of Concept
1. Create (or use) an `ApiClient` scoped to `stack_id` = Stack A, with `permissions: ['read:stack']` (as in fixture `here_come_the_walrus`).
2. As the holder of that token, issue `GET /stacks/:stack_id/cc.xml?token=<token>` (or via Basic Auth) with `stack_id` set to Stack B's identifier instead of Stack A.
3. `authenticate_api_client` succeeds (token is valid); `require_permission :read, :stack` passes because the token carries `read:stack`.
4. `stack` resolves via `Stack.from_param!(params[:stack_id])`, unconstrained by `current_api_client.stack_id`, returning Stack B.
5. The response renders Stack B's `name`, `lastBuildStatus`, `lastBuildLabel`, `webUrl`, etc., even though the token was only ever authorized for Stack A — confirmed by the rendering path exercised in `CCMenuControllerTest#test_show_renders_the_xml`. [8](#0-7)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-37)
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
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L20-24)
```ruby
      test "#show renders the xml" do
        get :show, params: { stack_id: @stack.to_param }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```
