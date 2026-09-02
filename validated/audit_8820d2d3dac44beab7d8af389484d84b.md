### Title
CCMenu API endpoint bypasses ApiClient stack-scoping, letting a stack-scoped token read any stack's status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
The Orchard bug is a class of "verified-but-not-bound" flaw: a value used in a security check is not the same value that is actually consumed downstream. `shipit-engine`'s `Api::CCMenuController` has the same shape: an `ApiClient` token can be scoped to a single stack (`ApiClient#stack`), and `Api::BaseController` is supposed to enforce that scoping for every resource lookup via its `stacks`/`stack` helpers — but `CCMenuController` overrides `stack` with an unscoped lookup, so the stack a token is *authorized for* is never the stack that is actually *read*.

### Finding Description
`Shipit::Api::BaseController` defines the intended binding between a token and the stacks it may touch: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the `ApiClient` is scoped to one stack, and `stack` resolves `params[:stack_id]` *through* that restricted relation via `stacks.from_param!`. This is how `Shipit::ApiClient` (which has an optional `belongs_to :stack`) is meant to limit a token to a single stack while still granting it a scope-level permission like `read:stack`: [2](#0-1) 

`ApiClient#check_permissions!` only checks that `"read:stack"` is present in the client's `permissions` array — it never checks which stack is being accessed; that check is only performed by the `stacks`/`stack` scoping in `BaseController`.

`Api::CCMenuController`, however, defines its own `stack` method that does not go through `stacks` at all: [3](#0-2) 

`stack` resolves `Stack.from_param!(params[:stack_id])` directly against the entire `Stack` table, completely bypassing the `current_api_client.stack_id` restriction. The equality that should hold — `current_api_client.stack_id == stack.id` (or "no restriction" when the client is unscoped) — is never enforced here; only the presence of the `read:stack` string in `permissions` is checked, and that permission is not stack-specific.

This is a direct analog of the reported bug class: the "authorization" step (checking `read:stack` on the token) is decoupled from the "binding" step (which stack record is actually acted upon), exactly like the Orchard gadget's `q_mul_2` equality check being decoupled from the real base point.

### Impact Explanation
Any `ApiClient` with `read:stack` permission — including one that is explicitly scoped to a single stack via `ApiClient#stack` (the exact mechanism `CCMenuUrlController` uses to mint self-service, single-stack-scoped tokens for the CI status widget, see `app/controllers/shipit/ccmenu_url_controller.rb`) — can be replayed against `GET /api/:stack_id/ccmenu.xml` for **any other stack_id**, not just the one it was scoped to. This discloses that stack's lock state, last build status/label/time and web URL — data the token holder was never authorized to see. This matches the "High" bucket in scope: unauthorized read of stack state.

### Likelihood Explanation
The `stack_id` is a simple URL path parameter and the only credential required is a valid, already-authenticated `ApiClient` token — the same kind of token the app itself mints for a single stack via `CCMenuUrlController#fetch`. No special privilege beyond having a token scoped to *some* stack is needed to read the state of a *different* stack, and the divergent `stack` override is a straightforward, deterministic code path (not a race or timing issue).

### Recommendation
Remove `CCMenuController`'s private `stack` override, or make it call `stacks.from_param!(params[:stack_id])` (the `BaseController` helper) instead of `Stack.from_param!`, so the client's `stack_id` scoping is enforced consistently across all API controllers.

### Proof of Concept
1. As a user with access only to Stack A, hit `GET /:stack_A_id/ccmenu_url` to obtain a `read:stack`-permissioned `ApiClient` token scoped to Stack A (via `CCMenuUrlController#fetch`).
2. Call `GET /api/:stack_B_id/ccmenu.xml?token=<token>` for an unrelated Stack B.
3. Observe that `CCMenuController#stack` resolves Stack B via `Stack.from_param!` (bypassing the `current_api_client.stack_id` == Stack A check), and the response renders Stack B's lock/build status — data the token was never authorized to access.

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

**File:** app/models/shipit/api_client.rb (L1-46)
```ruby
# frozen_string_literal: true

module Shipit
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-36)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```
