### Title
API stack-scoping bypass in `Api::CCMenuController` allows a stack-scoped `ApiClient` token to read the CI/build status of any other stack - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::BaseController` enforces per-`ApiClient` stack scoping by resolving stacks through `stacks.from_param!`, where `stacks` is restricted to `current_api_client.stack_id` when the client is scoped to a single stack. `Api::CCMenuController` overrides the `stack` accessor to call `Stack.from_param!(params[:stack_id])` directly, bypassing that scoping entirely. Any valid `ApiClient` token with the `read:stack` permission — even one explicitly restricted to a single stack — can therefore fetch the CCTray/CI status XML (build status, activity, last build time/label, web URL) of any stack in the installation by supplying an arbitrary `stack_id`.

### Finding Description
`Api::BaseController#stack` and `#stacks` implement the intended scoping binding: a client scoped to a stack (`current_api_client.stack_id?`) may only resolve stacks from that restricted set. [1](#0-0) 

`Api::CCMenuController` redefines `stack`, ignoring the scoped `stacks` helper and resolving directly against the global `Stack` relation: [2](#0-1) 

It also overrides `authenticate_api_client` to additionally accept a `params[:token]` query-string credential (intended to support the CCMenu URL feature), falling back to the parent's Basic Auth handling only if that fails: [3](#0-2) 

The only authorization check applied is `require_permission :read, :stack`, which merely checks that `"read:stack"` is present in the client's `permissions` array — it does not check that the requested `stack_id` matches the client's scoped `stack_id`. [4](#0-3) [5](#0-4) 

The equality that should hold — `token.authorised_stack == stack_touched_by_request` — is broken here: `CCMenuController` substitutes the unscoped `Stack.from_param!` for the scoped `stacks.from_param!` used everywhere else (e.g. `Api::StacksController#stack`, which is inherited unmodified from `BaseController`).

### Impact Explanation
This is a High-severity issue per the rules ("unauthenticated read of stack state ... via a valid but improperly scoped token"). A token intentionally created and scoped to one repository/stack (e.g. via `CCMenuUrlController#client`, which explicitly creates a stack-scoped `ApiClient` with `permissions: %w[read:stack]`) can be reused to read the build/CI status of every other stack in the Shipit installation, leaking cross-repository deploy state (last build status/time/label, whether it's currently building, and the stack's web URL) that the token holder was never authorized to see. [6](#0-5) 

### Likelihood Explanation
Exploitation requires possession of any valid `ApiClient` token with `read:stack` permission — which is exactly the class of token the `CCMenuUrlController` mints and hands out to browser extensions/CI dashboards for a single stack. No privileged account or additional secret is needed beyond that token; the attacker only needs to know or guess another stack's `stack_id` (owner/name/environment), which is not itself secret.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` helper (i.e. `stacks.from_param!(params[:stack_id])`) instead of the unscoped `Stack.from_param!`, consistent with `Api::BaseController` and other API controllers, so a stack-scoped client can only ever resolve to its authorized stack.

### Proof of Concept
1. Use `CCMenuUrlController#fetch` (or equivalent) to obtain an `ApiClient` scoped to `stack_id: A` with `permissions: ["read:stack"]`, and its `authentication_token`.
2. Call `GET /api/stacks/:owner/:repo/:env/ccmenu?token=<token>` where `:owner/:repo/:env` identifies a *different* stack `B` that the token was never scoped to.
3. `authenticate_api_client` succeeds because the token is cryptographically valid (`ApiClient.authenticate`), and `require_permission :read, :stack` passes because the token carries `read:stack`.
4. `stack` resolves via `Stack.from_param!(params[:stack_id])`, ignoring the client's `stack_id` restriction, and the response renders stack `B`'s CI/build status XML — data the token holder was not authorized to access.

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

**File:** app/models/shipit/api_client.rb (L38-45)
```ruby
    def check_permissions!(operation, scope)
      required_permission = "#{operation}:#{scope}"
      unless permissions.include?(required_permission)
        raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
      end

      true
    end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
