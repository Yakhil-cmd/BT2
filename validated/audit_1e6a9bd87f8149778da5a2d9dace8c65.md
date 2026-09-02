### Title
Stack-scoped ApiClient tokens can read CCMenu status of any stack, bypassing the stack scope binding - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The reported bug class is a mismatch between the scope an authorization credential is supposed to be bound to and the scope actually enforced when it is used. The equivalent binding in this engine is: *the stack an `ApiClient` token authorizes* vs *the stack the endpoint actually touches*. `Shipit::Api::CCMenuController` breaks this binding by resolving the target `Stack` directly from the request params instead of through the scoped relation that every other API controller uses to enforce `ApiClient#stack_id`.

### Finding Description
`Shipit::Api::BaseController` is designed so that a stack-scoped `ApiClient` (one created with a `stack_id`) can only see that one stack. This is implemented via the `stacks` helper: [1](#0-0) 

Controllers such as `Api::StacksController` and `Api::TasksController` derive their `stack`/`stacks` from this scoped relation, so a token restricted to stack A cannot resolve stack B.

`Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely: [2](#0-1) 

It calls `Stack.from_param!(params[:stack_id])` directly on the model, not `stacks.from_param!(params[:stack_id])`. The only permission check performed is `require_permission :read, :stack`, which merely verifies that the token has the `read:stack` permission string — it does not verify that the requested stack is the one the token is scoped to: [3](#0-2) 

The mismatch is exploitable via `Shipit::CCMenuUrlController`, which mints a per-user "CCMenu Client" token intended (from the UX and URL) to expose status for exactly one stack: [4](#0-3) 

Note that `ApiClient.create_with(permissions: %w[read:stack])` does **not** set `stack_id`, so the token created here is actually unscoped (able to see `Stack.all` per `BaseController#stacks`) — but even if it were scoped to a specific stack, `CCMenuController#show` would still ignore that scope because of the `Stack.from_param!` bypass shown above. `ApiClient#stack` is `optional: true` and `check_permissions!` only checks the operation/scope string: [5](#0-4) 

So, before/after: before the request, the token/URL implies "read access to stack X only"; after hitting `Api::CCMenuController#show` with a different `stack_id` param, the same token successfully returns full status (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) for any stack in the installation, including private/internal stacks the token holder was never meant to query through this credential.

### Impact Explanation
This is an authorization-scope bypass: an authenticated but stack-restricted credential is used to read state (`Stack`, `Deploy`) belonging to stacks outside its authorized scope — an unauthorized read of stack state via a credential whose entire design intent is per-stack isolation. Any CCMenu URL/token leaked (these are embedded in plaintext query strings, designed to be pasted into CI dashboard tools) grants the holder read access to every stack's deploy/build status in the Shipit instance, not just the one it was generated for.

### Likelihood Explanation
No special privileges beyond already holding one such token/URL are required — an attacker only needs to obtain any single CCMenu URL for any stack (these are routinely shared with third-party CI dashboards/status widgets, which is a lower bar than full API-client credentials with `read:stack` broadly). The scope bypass is reachable at the standard `api_stack_ccmenu_url` route by merely changing `stack_id`, so the flaw is trivial and reliably exploitable once a single token leaks.

### Recommendation
Have `Api::CCMenuController#stack` resolve through the scoped `stacks` relation (`stacks.from_param!(params[:stack_id])`) exactly like the other API controllers, so a stack-scoped `ApiClient` cannot read a stack outside its `stack_id`. Additionally, `CCMenuUrlController#client` should always set `stack_id: stack.id` on the created/found `ApiClient` so tokens are always narrowly scoped instead of relying on `creator`+`name` alone (which also causes token reuse/broadening across multiple stacks for the same user).

### Proof of Concept
1. User (or attacker who obtains a leaked CCMenu URL) visits `GET /stacks/:stack_a_id/ccmenu_url`, which returns a URL containing `token=<T>` for stack A, minted via `CCMenuUrlController#client` [6](#0-5) .
2. Attacker takes token `T` and requests `GET /api/stacks/:stack_b_id/ccmenu.xml?token=T` for an unrelated stack B.
3. `Api::BaseController#authenticate_api_client` authenticates `T` successfully via `ApiClient.authenticate` [7](#0-6) .
4. `require_permission :read, :stack` passes because `T` has the `read:stack` permission string, regardless of which stack is requested.
5. `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly, resolving stack B despite the token never having been scoped/intended for stack B, and returns stack B's full CCMenu status XML to the attacker.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-10)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack

      class NoDeploy
        def id
          0
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-22)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
```

**File:** app/models/shipit/api_client.rb (L8-45)
```ruby
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
