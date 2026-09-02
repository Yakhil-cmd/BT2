### Title
CCMenu API token stack-scope bypass allows reading build/deploy status of stacks outside the token's authorized scope - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::CCMenuController` resolves the target `stack` directly from the unvalidated `params[:stack_id]` against the global `Stack` table, instead of going through the stack-scoped query that every other API controller uses. This breaks the binding between the stack(s) an `ApiClient` token is authorized for and the stack whose data is actually served.

### Finding Description
Every other API endpoint resolves the target stack through `Api::BaseController#stack`, which is derived from `stacks`, a query explicitly scoped to the authenticated token's `stack_id` when the token is scoped to a single stack: [1](#0-0) 

`ApiClient` supports being bound to a single `Stack` via `belongs_to :stack, optional: true`, and permissions/authentication are checked separately from stack scoping: [2](#0-1) 

`Api::CCMenuController`, however, overrides `stack` and bypasses the scoped `stacks` relation entirely, resolving directly against `Stack.from_param!(params[:stack_id])`: [3](#0-2) 

The controller only enforces the *class-level* `read:stack` permission (`require_permission :read, :stack`), which is a boolean capability check on the `ApiClient#permissions` array and has nothing to do with which specific `stack_id` the client is bound to. There is no check that `params[:stack_id]` matches `current_api_client.stack_id` when the token is scoped.

The equality that should hold is:
`current_api_client.stack_id (the stack the token authorizes)` == `stack.id (the stack whose data is served)`

For every other controller this equality is enforced implicitly through `stacks.from_param!`. In `CCMenuController` it is not enforced at all — any token carrying the generic `read:stack` permission, regardless of its `stack_id` binding, can fetch CCMenu status (build name, last build status/label/time, web URL, lock state) for **any** stack in the Shipit instance simply by supplying a different `stack_id` in the URL.

### Impact Explanation
This is a broken access-control/authorization escalation: a deliberately stack-scoped token (e.g., handed out to an external CI dashboard, distributed via `CCMenuUrlController`, or created by an admin intentionally restricted to one stack) can be used to read build/deploy status of unrelated, unauthorized stacks. This matches the "unauthenticated read of stack state, task streams or deploy output" High-impact category — the read happens for a stack the presented credential was never authorized to touch, i.e., an unauthorized read of stack state via a legitimate-but-misscoped token.

### Likelihood Explanation
Exploitation requires only possession of any valid `ApiClient` token/`stack_id`-scoped token with `read:stack` permission (a routine, low-privilege credential many integrations hold) and knowledge/guessing of another stack's `to_param` (stack slugs are often predictable/enumerable, e.g. `repo/environment`). No GitHub credentials, webhook secrets, or elevated permissions are needed beyond a standard scoped API token.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` relation instead of the unscoped `Stack` model, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so it inherits the same `current_api_client.stack_id` scoping enforced everywhere else in the API.

### Proof of Concept
1. Admin creates (or the app auto-creates via `CCMenuUrlController#client`) an `ApiClient` scoped to `stack: stack_a` with `permissions: ['read:stack']`, and hands its `authentication_token` to an external CI status dashboard.
2. An attacker (or the dashboard operator) who only has this token requests:
   `GET /api/stack_b_owner/stack_b_repo/staging/ccmenu.xml?token=<stack_a-scoped-token>`
3. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` instead of `stacks.from_param!(params[:stack_id])`, the request succeeds and returns `stack_b`'s build name, last build status/label, deploy state, and lock status — data the token was never authorized to access.

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

**File:** app/models/shipit/api_client.rb (L4-45)
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
