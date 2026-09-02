## Finding

`Api::CCMenuController` bypasses the api-client-to-stack scoping that every other API endpoint enforces, letting a token authorized for one stack read build/deploy status for *any* stack.

### How stack scoping is supposed to work

`Api::BaseController` restricts the visible stacks to the ones an `ApiClient` is bound to: [1](#0-0) 

`ApiClient` can optionally `belongs_to :stack`, and permission checks only validate the permission string (e.g. `read:stack`), not which stack the request targets: [2](#0-1) 

The fixture `here_come_the_walrus` demonstrates a token intentionally scoped to a single stack (`shipit`) with only `read:stack`: [3](#0-2) 

`Api::StacksController` (via `BaseController#stack`/`#stacks`) correctly honors this: a stack-scoped client only sees its own stack (`test/controllers/api/stacks_controller_test.rb` line 188-198 shows `here_come_the_walrus` gets 0 results when querying another repo's stacks).

### The break

`Api::CCMenuController` overrides `#stack` to bypass the scoped `stacks` relation and resolves the stack directly from the request parameter, independent of which stack the authenticated `ApiClient` is bound to: [4](#0-3) 

`require_permission :read, :stack` only calls `ApiClient#check_permissions!`, which checks the permission list, never `current_api_client.stack`. So any client holding `read:stack` — including one deliberately scoped to a single stack such as `here_come_the_walrus`, or the low-privilege client minted per-user by `CCMenuUrlController` — can pass `stack_id: <any stack>` in the URL and receive that stack's CI/build status.

**Binding broken:** *stack a token authorises* (`ApiClient#stack`) ≠ *stack the request touches* (`params[:stack_id]` resolved via `Stack.from_param!` with no scope filter).

### Impact

This is an unauthenticated-relative-to-target-stack read of stack state (last build status/label/time, lock state) for stacks the token was never granted access to — matching the "High: unauthenticated read of stack state" category, since the whole point of scoping a client to a single stack (as the fixture and `CCMenuUrlController`'s per-user token issuance both do) is defeated for this one endpoint.

### Recommendation

Change `Api::CCMenuController#stack` to reuse the scoped `stacks` lookup from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of querying `Stack.from_param!` unscoped, so a stack-restricted `ApiClient` cannot read data for stacks outside its `stack_id`.

### Uncertainty

I could not fully verify at what times a `CCMenuUrlController`-issued client (`create_with(permissions: %w[read:stack])`, no explicit `stack:` set) is or isn't stack-scoped in production versus the `here_come_the_walrus`-style manually configured client — the vulnerability is clearest and most directly provable for any manually provisioned single-stack `ApiClient` (as in the fixture), which is a supported and documented configuration (`resources :api_clients` lets admins create clients scoped to a specific stack). I recommend a Devin session with full repo/test access to confirm behavior end-to-end and add a regression test (analogous to the existing `stacks_controller_test.rb` scoping tests) for `CCMenuControllerTest`.

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
