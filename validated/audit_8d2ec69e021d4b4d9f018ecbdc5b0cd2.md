### Title
Cross-stack build status disclosure via scoped API token in CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
Similar to the Illuminate `Redeemer` bug where a value computed for one context (a "starting" balance snapshot) is trusted after an intervening step that can act on a different context (an attacker-chosen adapter/PT type) than the one that was validated, `Api::CCMenuController` performs its authorization check against one binding (`current_api_client`'s general `read:stack` permission) but then resolves and serves data for a stack looked up independently of the binding that the token is actually scoped to.

### Finding Description
`Shipit::Api::BaseController` establishes the authorization binding "the stack the token is allowed to act on" via the `stacks` helper, which restricts the queryable stack set to `current_api_client.stack_id` when the `ApiClient` is scoped to a stack: [1](#0-0) 

`ApiClient` supports being scoped to a single stack (`belongs_to :stack, optional: true`), and permission checks (`check_permissions!`) only validate that the operation/scope string (e.g. `read:stack`) is present in the client's permission list — they never re-verify that the specific `stack_id` param matches the client's bound `stack_id`: [2](#0-1) 

That re-verification is instead expected to happen through the `stacks`/`stack` helper chain in `BaseController`. However, `Api::CCMenuController` overrides `stack` to bypass this scoping entirely, resolving the target stack directly from the request parameter instead of from the client-scoped `stacks` relation: [3](#0-2) 

This breaks the binding: `current_api_client.stack_id` (what the token is authorized for) ≠ the `stack_id` param used to render `#show` (what the code actually acts on). The `require_permission :read, :stack` before_action only checks that the string `"read:stack"` exists in the token's permission list — it says nothing about *which* stack — so any client holding a `read:stack`-scoped token (including ones legitimately created and bound to a single stack, since `ApiClient` supports per-stack scoping) can substitute an arbitrary `stack_id` in the request and successfully read another stack's data.

### Impact Explanation
`#show` renders the CCMenu project XML, exposing the requested stack's name, last build status/label/time and `webUrl`: [4](#0-3) 

This is an authorization escalation: a token intended to be scoped to a single stack's `read:stack` permission can be used to read build/deploy status of any other stack in the Shipit installation, i.e., "a stack a token authorizes vs. a stack it touches" — an unauthenticated-relative-to-scope read of stack state, matching the High-severity class of "unauthenticated read of stack state... " called out for this analog scan (here, read outside the token's authorized scope rather than fully unauthenticated).

### Likelihood Explanation
Any holder of a valid, stack-scoped `ApiClient` token with `read:stack` permission can trigger this by simply changing the `stack_id` route/query parameter — no additional privilege, secret, or special access is required beyond possessing one legitimately-scoped read-only token, which is a normal, low-privilege credential in this system (e.g. handed out for CI status badges).

### Recommendation
Remove the `stack` override in `Api::CCMenuController` (and the `authenticate_api_client` override that permits query-string tokens) so it inherits `BaseController#stack`, which resolves the stack through the client-scoped `stacks` relation instead of an unscoped `Stack.from_param!` lookup. If query-string token auth must remain for CCMenu, still route stack resolution through `stacks.from_param!` so the `current_api_client.stack_id` binding is enforced.

### Proof of Concept
1. Obtain (or self-issue via `CCMenuUrlController#fetch`, or via an admin-issued scoped API client) an `ApiClient` token bound to `stack_id = A` with permission `read:stack`.
2. Call `GET /api/stacks/:owner/:repo_of_stack_B/:env/ccmenu.xml?token=<token>` substituting a different, unauthorized stack `B`'s `owner/repo/environment` path in `stack_id`.
3. `authenticate_api_client` succeeds (valid token) and `require_permission :read, :stack` passes (token has `read:stack`), but `stack` resolves via `Stack.from_param!(params[:stack_id])` directly rather than the client-scoped `stacks` relation, so stack `B`'s deploy/build status is returned even though the token is only authorized for stack `A`. [5](#0-4)

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
