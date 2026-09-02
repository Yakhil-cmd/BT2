### Title
Unscoped ApiClient granted for a stack-specific CCMenu URL bypasses the stack-authorization binding - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
The report's bug class (front-running/binding break between the entity verified and the entity actually acted upon) has a concrete analog in Shipit's CCMenu token flow: the `ApiClient` created for a user's stack-specific "CCMenu URL" is never bound to the stack the user requested it for, and the endpoint that consumes the token bypasses the client's own stack-scoping mechanism entirely.

### Finding Description
`CCMenuUrlController#client` mints (or reuses) an `ApiClient` scoped only by `creator` and `name`, granting `read:stack` permission, but never assigns `stack:` to bind the token to the specific stack the URL was generated for: [1](#0-0) 

Compare this to the scoping mechanism the rest of the API relies on: `ApiClient` supports an optional `stack` association, and `Api::BaseController#stacks` is supposed to restrict visibility to that stack when `stack_id?` is true: [2](#0-1) 

Because the CCMenu client is created without a `stack:` attribute, `current_api_client.stack_id?` is always `false` for it, so even the intended scoping mechanism would grant it visibility into every stack (`Stack.all`) — not just the one from the URL the user generated it for. Compounding this, `Api::CCMenuController` doesn't even use the scoped `stacks` helper: it overrides `stack` to do a raw, unscoped lookup: [3](#0-2) 

The only check performed is `require_permission :read, :stack`, which merely confirms the *permission string* `read:stack` is present on the token — it does not verify the token is authorized for *this particular* `stack_id`: [4](#0-3) 

This is the same class of bug as the report: a value that is supposed to bind an authorization decision (the stack the token was minted for) is never actually enforced at the point the resource is touched (`Stack.from_param!(params[:stack_id])` accepts any stack id). The equality that should hold — `token.authorized_stack == stack_being_read` — is never checked; instead any stack id in the URL is honored as long as the bearer holds *any* `read:stack`-permissioned token.

### Impact Explanation
The CCMenu token is designed to be embedded in third-party CI dashboard tools via URL query string (`?token=...`), i.e., treated as a low-sensitivity, narrowly-scoped credential for one stack's build status. Because the token is not stack-bound and the controller performs an unscoped `Stack.from_param!` lookup, possession of a single CCMenu token (leaked via a dashboard, browser history, proxy logs, etc.) grants unauthenticated read access to build/deploy status (`stack.deploys_and_rollbacks`) for **every stack in the Shipit instance**, not just the one it was generated for. This is an unauthorized read of stack/task state across stacks the token holder was never granted — matching the "High: unauthenticated read of stack state, task streams, or deploy output" impact category.

### Likelihood Explanation
Likelihood is high in any multi-stack Shipit deployment: any user with legitimate access to request a CCMenu URL for one stack automatically receives a token that, by construction, works for all stacks, and no additional action (privilege escalation, secret compromise, etc.) is needed — simply changing the `stack_id` query parameter with a leaked/valid CCMenu token is sufficient.

### Recommendation
- Set `stack:` when creating/finding the `ApiClient` in `CCMenuUrlController#client`, scoping it to the specific stack.
- Remove the `stack` method override in `Api::CCMenuController` and instead use the scoped `stacks.from_param!(params[:stack_id])` (as `Api::BaseController` does for other controllers), so a stack-scoped client can only read the stack it was issued for.
- Consider creating a distinct `ApiClient` per stack (rather than `find_or_create_by!(creator:, name:)` alone) so that requesting a CCMenu URL for stack B does not silently reuse/upgrade a token originally scoped (or intended to be scoped) to stack A.

### Proof of Concept
1. User with access to Stack A visits the CCMenu URL page for Stack A; `CCMenuUrlController#fetch` creates/reuses an `ApiClient` named "CCMenu Client" with `permissions: ['read:stack']` and no `stack` binding, returning a URL like `/api/stacks/A/ccmenu.xml?token=<T>`.
2. Anyone who obtains `<T>` (e.g., via the dashboard tool, logs, browser history) requests `/api/stacks/B/ccmenu.xml?token=<T>` for an unrelated Stack B.
3. `Api::CCMenuController#authenticate_api_client` validates `<T>` via `ApiClient.authenticate` (signature-only check, no stack check) [5](#0-4) ; `require_permission :read, :stack` passes because the token has `read:stack`; `stack` resolves via unscoped `Stack.from_param!('B')` [6](#0-5) .
4. The response renders Stack B's deploy/build status XML, even though the token was only ever intended for Stack A.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-22)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```
