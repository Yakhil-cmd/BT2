### Title
`CCMenuUrlController#fetch` issues a globally-scoped `read:stack` API token because `ApiClient#stack_id` is never set - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`CCMenuUrlController#client` finds-or-creates an `ApiClient` scoped only by `creator` and `name: 'CCMenu Client'`, never passing a `stack:` association, so `stack_id` stays `nil` for that client forever regardless of which `stack_id` was requested. Because `Api::BaseController#stacks` treats a nil `stack_id` as "no restriction" (`Stack.all`), the resulting CCMenu token is not scoped to the stack it was issued for — it authenticates `read:stack` access to every stack in the installation.

### Finding Description
The claimed binding — "the `ApiClient` returned by `#client` for a `fetch` on stack X has `stack_id == X.id`" — is false. `client` is: [1](#0-0) 
`find_or_create_by!(creator: current_user, name: 'CCMenu Client')` looks up/creates by `creator` + `name` only; `stack:` is never assigned on create, and `find_or_create_by!` never updates an already-existing record. So for a given user, the very first call to `#fetch` (for any stack) creates one `ApiClient` row with `stack_id = nil`, and every subsequent call — for any other stack — returns that same row unchanged.

The consumer of this token is `Api::BaseController#stacks`: [2](#0-1) 
`current_api_client.stack_id?` is `false` when `stack_id` is `nil`, so the scope collapses to `Stack.all` — i.e., the token is not restricted to any single stack at all, and can be used against `GET /api/stacks/:stack_id/ccmenu.xml` (or any other `read:stack` endpoint) for every stack in the instance, not merely stacks the user previously fetched a URL for.

`CCMenuUrlController#fetch` itself performs no per-stack authorization check before minting/reusing the token — it simply does `Stack.from_param!(params[:stack_id])` and hands back a URL containing `client.authentication_token`, so any authenticated Shipit user can request this for arbitrary `stack_id` values and always get back the same unrestricted token.

Existing guards do not prevent this: `verify_signature`, webhook checks, and `require_permission!`/`check_permissions!` correctly gate the `read:stack` *permission* on the `ApiClient`, but none of them validate that `stack_id` actually matches the stack the caller is trying to read — because it's `nil`, the scoping check in `stacks` is bypassed entirely by design of that ternary.

### Impact Explanation
Any authenticated Shipit user who visits `GET /stacks/:stack_id/ccmenu_url` receives a bearer token (`ApiClient#authentication_token`) that, when used against the JSON/XML API with `read:stack` permission, can read stack state (build status, last deploy, environment, lock status, etc.) for **every stack in the Shipit instance**, not just the one named in the URL. This is a cross-tenant authorization bypass: a user with legitimate access to one repository's stack obtains a durable credential (usable outside any Shipit session, via HTTP Basic/query-string token) that discloses deploy/build state of stacks belonging to other teams/repositories. This matches the High-severity category "unauthorized read of stack state ... " since the resulting token requires no ongoing Shipit session to use.

### Likelihood Explanation
Preconditions are minimal: the attacker only needs a normal authenticated Shipit account (login via the configured GitHub org) and the ability to load `/stacks/:stack_id/ccmenu_url` for any `stack_id`, which the controller does not gate per-stack. No GitHub secrets, webhook secrets, or `api_clients_secret` are needed. The token is reusable indefinitely (same DB row reused every time via `find_or_create_by!`), so a single request establishes persistent, stack-unrestricted read access.

### Recommendation
Scope the `ApiClient` per-stack and enforce it consistently:
- In `CCMenuUrlController#client`, include `stack:` in both the `create_with` attributes and the `find_or_create_by!` lookup keys (e.g. `find_or_create_by!(creator: current_user, stack: stack, name: 'CCMenu Client')`), so a distinct `ApiClient` (with correct `stack_id`) is created per stack.
- Defensively, change `Api::BaseController#stacks` to never fall back to `Stack.all` when `stack_id` is unset for a client that is supposed to be stack-scoped, or make `stack_id` non-nullable for tokens created via this flow.

### Proof of Concept
```ruby
# test/controllers/ccmenu_url_controller_test.rb
require 'test_helper'

module Shipit
  class CCMenuUrlControllerTest < ActionController::TestCase
    setup do
      @user = shipit_users(:walrus) # any authenticated user
      session[:user_id] = @user.id
      @stack_a = shipit_stacks(:shipit)
      @stack_b = Stack.create!(repository: Repository.new(owner: 'other', name: 'repo'), branch: 'main')
    end

    test "token issued for stack A is the same client and authorizes stack B" do
      get :fetch, params: { stack_id: @stack_a.to_param }
      token_a = URI(JSON.parse(response.body)['ccmenu_url']).query[/token=([^&]+)/, 1]
      client = ApiClient.find_by(creator: @user, name: 'CCMenu Client')

      get :fetch, params: { stack_id: @stack_b.to_param }
      token_b = URI(JSON.parse(response.body)['ccmenu_url']).query[/token=([^&]+)/, 1]

      # BROKEN BINDING: both calls return the SAME client with nil stack_id
      assert_equal client.id, ApiClient.find_by(creator: @user, name: 'CCMenu Client').id
      assert_nil client.stack_id
      assert_equal token_a, token_b # same token reused across stacks

      # Prove the token authorizes reads on BOTH stacks via the API
      get "/api/stacks/#{@stack_a.to_param}/ccmenu.xml", params: { token: token_a }
      assert_response :ok
      get "/api/stacks/#{@stack_b.to_param}/ccmenu.xml", params: { token: token_a }
      assert_response :ok # should be :forbidden/:not_found if properly scoped
    end
  end
end
```

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```
