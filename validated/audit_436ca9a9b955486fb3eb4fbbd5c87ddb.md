### Title
CCMenu tokens are not bound to the stack they are generated for, granting global `read:stack` access - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
The reported bug class is that an authorization credential omits binding parameters (chain, destination contract, expiry) that are needed to keep it scoped to the transaction/context it was meant to authorize, letting it be replayed in an unintended context. The equivalent binding in Shipit is: **the stack a `ApiClient` token is generated to expose vs. the stack(s) it can actually be used to read**. `CCMenuUrlController#client` mints an `ApiClient` token while visiting a specific stack's CCMenu URL, but never binds that token to that stack, so the resulting token authorizes read access to every stack in the installation.

### Finding Description
`CCMenuUrlController#fetch` builds a shareable CI-status URL for the current stack and embeds an `ApiClient` authentication token in its query string: [1](#0-0) 

The client is created (or reused) with:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
```
Note that `stack:` is never passed to `create_with`/`find_or_create_by!`, so the resulting `ApiClient` record has `stack_id == nil`.

`ApiClient` authorization is enforced purely by matching a `operation:scope` string against the `permissions` array — it has no notion of "for which stack": [2](#0-1) 

Whether a token is restricted to one stack is determined solely by whether `ApiClient#stack_id` is set, which `Api::BaseController#stacks` uses to scope queries: [3](#0-2) 

Because the CCMenu-generated token has `stack_id == nil`, this scoping mechanism treats it as an "all stacks" token — anywhere `read:stack` is required (the general `Api::StacksController#index`/`#show`, `Api::CommitsController`, `Api::TasksController`, `Api::CCMenuController`, etc.), `stacks` resolves to `Stack.all` rather than the single stack the CCMenu URL was generated for: [4](#0-3) [5](#0-4) 

The `authentication_token` itself only encodes the `ApiClient` row id (analogous to the report's "nonce-only" token that omits the intended destination): [6](#0-5) 

So the equality that should hold — *stack the token was minted to expose == stack(s) the token can be used to read* — is broken: a token created while looking at `stack A`'s CCMenu page instead grants `read:stack` for stack B, C, D, ... (every stack in the Shipit instance), including private/unrelated repositories.

### Impact Explanation
CCMenu/CCTray URLs are specifically designed to be embedded in third-party dashboards, IDE plugins, or status-monitor tools, and are frequently pasted into chat, wikis, or dashboards, or logged by intermediate proxies — they are treated by users as "read-only status for this one project," which is the entire point of `CCMenuUrlController`. Leakage of a single such URL/token (a very plausible, low-friction event given its intended sharing pattern) grants an unprivileged holder `read:stack` on **every** stack managed by that Shipit instance: build/deploy status, commit history, task/deploy listings, and any other endpoint gated only by `read:stack`. This matches the "High — unauthenticated/unauthorized read of stack state" bucket, since the credential's read scope silently escalates far beyond the single stack the sharer intended and authorized.

### Likelihood Explanation
No special privilege is required beyond obtaining a copy of the token that a user already intended to share externally (that is the token's designed purpose). Because the same `ApiClient` record ("CCMenu Client") is reused (`find_or_create_by!`) across every stack the user visits via CCMenu, the very first token a user generates for any single stack immediately doubles as a skeleton key for all stacks — no additional action, misconfiguration, or privileged access is needed to trigger the over-broad grant; it exists by construction from the moment `CCMenuUrlController#fetch` is first called for any stack.

### Recommendation
Bind the token to the stack it is minted for: pass `stack:` into `ApiClient.create_with(...)` / `find_or_create_by!` in `CCMenuUrlController#client` (scoping the lookup by `creator`, `name`, and `stack`), so `ApiClient#stack_id` is populated and `Api::BaseController#stacks` correctly restricts the token to the originating stack. Additionally, `Api::CCMenuController#stack` should use the scoped `stacks.from_param!(params[:stack_id])` helper (as other API controllers do) instead of calling `Stack.from_param!` directly, so that stack-scoped tokens are actually enforced even at that endpoint.

### Proof of Concept
1. User A visits `/ccmenu/stack-A/fetch` (via `CCMenuUrlController#fetch`); Shipit creates/reuses an `ApiClient` named "CCMenu Client" for User A with `permissions: ['read:stack']` and `stack_id: nil`, and returns a URL like `.../api/stack-A/ccmenu.xml?token=<T>`.
2. `<T>` leaks (shared dashboard, chat log, proxy log, screenshot, etc.) to an unprivileged party.
3. The attacker uses `<T>` as Basic Auth credentials against `Api::StacksController#index`/`#show` or `/api/stack-B/ccmenu.xml` for a *different* stack B that User A never intended to expose.
4. Because `ApiClient#stack_id` is `nil`, `Api::BaseController#stacks` returns `Stack.all`, and the request succeeds, exposing stack B's status/build/commit data — a stack never authorized by the token's original purpose.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-18)
```ruby
  class CCMenuUrlController < ShipitController
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
```

**File:** app/models/shipit/api_client.rb (L24-46)
```ruby
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```
