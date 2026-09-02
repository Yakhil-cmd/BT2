### Title
CCMenu API Token Scope Bypass Allows Reading Any Stack's Deploy Status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the generic stack-lookup helper used by `BaseController` with one that ignores the requesting `ApiClient`'s stack scope, so a token that is authorized (and was created) to read a single stack can be used to read the CCMenu/deploy status of every other stack in the Shipit instance.

### Finding Description
`Shipit::Api::BaseController` scopes stack lookups to the authenticated `ApiClient`'s assigned stack when one is set: [1](#0-0) 

`Shipit::ApiClient` supports an optional `stack` association, and `check_permissions!` only checks whether the client's `permissions` array contains `"read:stack"` — it never checks which specific stack the token is bound to: [2](#0-1) 

The read-only CCMenu token is minted by `CCMenuUrlController`, scoped only to the single stack the user was viewing when they requested the CCMenu URL: [3](#0-2) 

However, `Shipit::Api::CCMenuController` re-implements both `authenticate_api_client` (to accept the token from the query string) and `stack` (to look the stack up directly by `params[:stack_id]`), completely bypassing the `stacks`/`stack_id?` scoping that `BaseController` provides: [4](#0-3) 

The `require_permission :read, :stack` before-action only verifies that the token has the generic `read:stack` permission bit (which every CCMenu token has), not that the requested `stack_id` matches the token's bound `stack`. As a result, the equality the token is meant to enforce — "the stack an `ApiClient` token authorizes access to" == "the stack the request actually touches" — is broken: any valid CCMenu token can be replayed against `/api/*any-other-stack*/cc.xml` (or the underlying `Api::CCMenuController#show` route) to fetch deploy state for a completely different stack.

### Impact Explanation
This allows unauthenticated (relative to the target stack) disclosure of stack/deploy state: the requester can read `stack.deploys_and_rollbacks.last` (last build status/label/time, lock status) for any stack in the instance, including private/internal stacks the token holder was never granted access to. This matches the High-impact category of "unauthenticated read of stack state, task streams or deploy output," since a token that is only supposed to authorize reading one stack can be used to read every stack.

### Likelihood Explanation
Likelihood is high in practice: CCMenu tokens are automatically generated and embedded in a plain URL (`ccmenu_url`) any authenticated Shipit user can request for any stack they can view, via `CCMenuUrlController#fetch`. Any holder of one such URL/token (which may be shared, bookmarked, or leaked in CI dashboard configs) can trivially change the `stack_id` in the request path to enumerate other stacks, requiring no elevated privileges, no additional secrets, and no interaction with the target stack's owners.

### Recommendation
Make `Shipit::Api::CCMenuController#stack` (and `#authenticate_api_client`) respect the same scoping as `BaseController`: look the stack up through `stacks` (which already restricts to `current_api_client.stack_id` when present) instead of calling `Stack.from_param!(params[:stack_id])` directly. Concretely, replace the private `stack` method with `@stack ||= stacks.from_param!(params[:stack_id])`, keeping the custom `authenticate_api_client` for query-string tokens.

### Proof of Concept
1. As a legitimate Shipit user with access to Stack A only, load Stack A's page; the app calls `CCMenuUrlController#fetch`, which creates (or reuses) an `ApiClient` scoped to Stack A with `permissions: ["read:stack"]` and returns a URL like:
   `GET /api/<stack_a_id>/cc.xml?token=<token>` [3](#0-2) 
2. Take the same `token` value and issue a request against a different, unrelated stack B that the user has no access to:
   `GET /api/<stack_b_id>/cc.xml?token=<token>`
3. In `Api::CCMenuController#authenticate_api_client`, `ApiClient.authenticate(params[:token])` succeeds (the token is cryptographically valid — it's just scoped to Stack A).
4. `require_permission :read, :stack` passes because the token has the `read:stack` permission bit.
5. `stack` resolves via `Stack.from_param!(params[:stack_id])` to Stack B (ignoring the token's `stack_id`), and `show` renders Stack B's `deploys_and_rollbacks.last` build status/label/time in the XML response — disclosing Stack B's deploy state to a user who was never granted access to it.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-22)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
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
