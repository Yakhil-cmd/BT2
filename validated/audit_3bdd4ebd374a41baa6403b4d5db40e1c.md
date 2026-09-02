### Title
CCMenu API token created without stack scope, and `CCMenuController` ignores any scope that does exist - ([File: app/controllers/shipit/ccmenu_url_controller.rb], [File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The `blacklist_user_ix` bug is a case where a privileged action (refund) is applied without updating the corresponding trust flag (`is_blacklisted`) that should have been bound to it, letting the user keep operating as if nothing happened. The analogous binding in Shipit is "the stack an `ApiClient` token is authorized for" vs. "the stack the CCMenu endpoint actually serves." Both the token-issuance path and the token-consumption path fail to enforce this binding.

### Finding Description
`CCMenuUrlController#client` mints an `ApiClient` for the current user without ever setting `stack:`: [1](#0-0) 

Because `ApiClient.stack` is left `nil`, `BaseController#stacks` treats this client as unscoped and grants it read access to **every** stack in the installation: [2](#0-1) 

Independently, `Api::CCMenuController` never even goes through that `stacks`/`stack` scoping logic. It overrides `stack` to look the stack up directly with `Stack.from_param!(params[:stack_id])`, completely bypassing whatever scope `current_api_client.stack_id` would otherwise enforce: [3](#0-2) 

So even in the hypothetical case where an `ApiClient` *were* correctly scoped to one stack (as e.g. `here_come_the_walrus` is in the fixtures: `stack: shipit`), the `CCMenuController#show` action would still serve status for any `stack_id` supplied in the URL, because the controller's own `stack` method never consults `current_api_client.stack_id`.

The binding that should hold is:
`stack_id bound to the ApiClient at issuance == stack_id the CCMenu endpoint actually renders`

Before the attacker's request: a "CCMenu Client" token is generated while viewing stack A's settings page, intended to expose only stack A's build status to an external, unauthenticated CI-dashboard tool.
After: that same token (`GET /api/:stack_id/ccmenu?token=...`), with no Shipit session, no team membership check, and no further authorization, can be replayed against any other stack's `stack_id` and returns that stack's build/deploy status.

### Impact Explanation
This grants **unauthenticated read of stack state / deploy status for every stack in the Shipit instance** to anyone who obtains one CCMenu token — and CCMenu URLs are explicitly designed to be embedded in third-party, unauthenticated tools (CI dashboards, build-status widgets), so leakage of the token outside the trusted context is the expected usage pattern, not an edge case. This matches the High-impact category "unauthenticated read of stack state, task streams or deploy output" from the scan's impact list.

### Likelihood Explanation
Likelihood is Medium-High: any authenticated Shipit user can trigger `CCMenuUrlController#fetch` for a stack, obtain a token intended to be scoped, and that token works globally with zero additional privilege check — no admin action or race condition needed, just calling the existing "settings" feature and then using the returned token against a different `stack_id`.

### Recommendation
1. In `CCMenuUrlController#client`, create/find the `ApiClient` scoped to the specific stack, e.g. `ApiClient.create_with(permissions: %w[read:stack], stack:)`.
2. In `Api::CCMenuController`, remove the private `stack` override and instead use the inherited `stacks`/`stack` methods from `BaseController` (or explicitly check `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id`) so the endpoint honors whatever scope the authenticating `ApiClient` carries.

### Proof of Concept
1. As any authenticated Shipit user with access to Stack A, hit the "CCMenu URL" action for Stack A (`CCMenuUrlController#fetch`, e.g. via the stack settings page). This creates/reuses an `ApiClient` named "CCMenu Client" for that user with `permissions: ['read:stack']` and `stack_id: nil`, and returns a signed `token`.
2. Take that `token` and call `GET /api/:stack_b_id/ccmenu?token=<token>` for Stack B — a stack the user was never meant to expose via this token.
3. Observe `Api::CCMenuController#show` returns Stack B's build/deploy status (`assert_response :ok`), because `authenticate_api_client` only validates the token's signature/permission set, and the controller's own `stack` method (`Stack.from_param!(params[:stack_id])`) never checks `current_api_client.stack_id` against the requested `stack_id`.

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
