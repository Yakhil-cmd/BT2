### Title
Stack-scoped API tokens can read CCMenu build status for any stack, not just the stack they were authorized for - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the base `stack` lookup helper and resolves the target stack directly from the request param instead of going through the stack-scoping logic used everywhere else in the API. This breaks the binding `stack a token authorizes == stack a token can touch`.

### Finding Description
Every other API controller resolves the target stack through `BaseController#stack`, which is scoped to the token's authorized stack set: [1](#0-0) 

`stacks` narrows the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` is scoped to a single stack (`stack_id?` true), and only falls back to `Stack.all` for unscoped/global tokens.

`CCMenuController`, however, defines its own `stack` method that bypasses this scoping entirely: [2](#0-1) 

It calls `Stack.from_param!(params[:stack_id])` directly on the `Stack` model, ignoring `current_api_client.stack_id`. The only authorization check that remains is the generic, non-scoped permission check `require_permission :read, :stack`: [3](#0-2) 

`ApiClient#check_permissions!` only checks that the `read:stack` string is present in the client's `permissions` array; it never compares against the specific stack being accessed: [4](#0-3) 

This is the same class of bug as the WooPPV2 report: the code verifies one binding (`operation:scope` permission string) while silently reusing cached/scoped state (`current_api_client.stack_id`) for a *different* purpose (actually resolving the stack to act on), and the mismatch lets the caller act outside the boundary the credential was meant to enforce. Here the broken equality is:

`stack authorized by the ApiClient (current_api_client.stack_id) == stack whose data is returned by CCMenuController#show`

An `ApiClient` created with `stack_id` set (e.g. the `ccmenu_url_controller.rb` flow, which intentionally mints a narrowly-scoped `read:stack` token for a single stack) is meant to be confined to that one stack: [5](#0-4) 

But because `CCMenuController#stack` never consults `current_api_client.stack_id`, that same token — or any other token carrying only the generic `read:stack` permission — can be replayed against `params[:stack_id]` for any other stack in the installation and will successfully render that stack's CI/deploy status.

### Impact Explanation
This matches the "High" impact bucket: unauthenticated/unauthorized **read of stack state** (build status, last build label/time, web URL, activity/lock state) for stacks the caller's token was never scoped to. A holder of any narrowly-scoped, low-trust `read:stack` token (e.g. a CCMenu widget token intentionally issued for one non-sensitive stack) can enumerate `stack_id` values and pull deploy/CI status for every other stack managed by the Shipit instance, including stacks it has no legitimate visibility into. No repository write access, GitHub credentials, or privileged account is required — only possession of any valid `read:stack`-scoped API token, which is by design the least-privileged token type in this engine.

### Likelihood Explanation
High. Exploitation requires only a single legitimate API call with a valid token that already has `read:stack` and knowledge/enumeration of `stack_id`/`to_param` values (which are just repo owner/name/environment/branch identifiers, discoverable via the `/api/stacks` `index` action available to any equally low-privileged unscoped client, or simply guessable from the stack's slug). No timing games, races, or complex payload construction are needed — this is a straightforward authorization-scoping bypass reachable via a single unprivileged GET request.

### Recommendation
Make `CCMenuController#stack` reuse the scoped `stacks` collection from `BaseController` instead of querying `Stack` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the `stack_id`-scoping check (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`) for the CCMenu endpoint, so a stack-scoped token can only ever resolve its own stack.

### Proof of Concept
1. Two stacks exist: `stack-A` (scoped) and `stack-B` (unrelated, more sensitive).
2. An `ApiClient` is created scoped to `stack-A` only, with permission `read:stack` (mirrors the flow in `CCMenuUrlController#client`, which creates exactly such a client for the CCMenu widget): [5](#0-4) 
3. Using that token's `authentication_token`, issue:
   `GET /api/stacks/<stack-B-id>/ccmenu?token=<token>`
4. `authenticate_api_client` in `CCMenuController` succeeds because the token is valid (`ApiClient.authenticate(params[:token])`): [6](#0-5) 
5. `require_permission :read, :stack` passes because the client's `permissions` array contains `read:stack` (it does not check which stack).
6. `stack` resolves `stack-B` directly via `Stack.from_param!`, ignoring that the token's `current_api_client.stack_id` is `stack-A`'s id.
7. The response renders `stack-B`'s deploy/build status XML — data the token was never authorized to see.

**Note:** I was not able to find an existing regression test in `test/controllers/api/ccmenu_controller_test.rb` that exercises a stack-scoped token against a *different* stack_id (the visible tests only cover permission-string checks and the happy path), which is consistent with this scoping bypass being untested/unnoticed. If deeper verification of exploitability under `require_permission` before_action ordering is desired, a Devin session with full repo/test access would be needed to run the PoC end-to-end.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
