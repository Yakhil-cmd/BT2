## Title
`Api::CCMenuController` never checks the token-authorized stack against the requested stack, letting any `read:stack` `ApiClient` token read any stack's build/deploy status - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
The `provide()` bug class is: an authorization primitive (withdrawal request) is validated once at issuance but never re-checked/reset against the actual action performed later, so the authorization outlives its intended scope. In Shipit, the analogous binding is: `ApiClient#stack_id` is meant to scope a token to a single stack (`stacks = current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` in `app/controllers/shipit/api/base_controller.rb:74-76`), but `Api::CCMenuController` never consults this scoped relation.

### Finding Description
`Api::CCMenuController#stack` is overridden to bypass the scoped `stacks` helper entirely: [1](#0-0) 
It calls `Stack.from_param!(params[:stack_id])` directly on the full `Stack` relation instead of the token-scoped `stacks.from_param!(params[:stack_id])` used elsewhere (e.g. `app/controllers/shipit/api/base_controller.rb:78-80`). The controller's only permission check is generic: [2](#0-1) 
`require_permission :read, :stack` only verifies the token carries the `read:stack` permission string; it never verifies the token's `stack_id` (if any) equals the `stack_id` param being requested.

Compounding this, the primary way this token is minted (`CCMenuUrlController`) never sets `stack:` on the created `ApiClient` at all: [3](#0-2) 
Because `find_or_create_by!(creator: current_user, name: 'CCMenu Client')` matches only on `creator`/`name`, the same unscoped token (`stack_id` is `nil`) is reused/returned for every stack the user ever calls `fetch` on, which per the base controller's scoping logic (`stack_id?` false → `Stack.all`) already grants read access to every stack. Even for a hand-crafted `ApiClient` that *does* have `stack_id` set (e.g. via `app/controllers/shipit/api_clients_controller.rb`), the override in `Api::CCMenuController#stack` still ignores that scoping and permits any `stack_id` param.

- Before: intended equality — `token.stack_id == requested_stack_id` (or `Stack.all` only for globally-scoped admin tokens).
- After: `Api::CCMenuController` enforces only `token.permissions.include?("read:stack")`, with the `stack_id` param unconstrained by the token's own `stack_id`.

### Impact Explanation
This is an unauthenticated-scope escalation into stack read access: a valid `read:stack` `ApiClient` token — including the "CCMenu Client" tokens embedded in plaintext in shareable CCMenu URLs (a build-monitor integration) — can be used to fetch `Api::CCMenuController#show`'s XML for **any** stack in the Shipit installation (not just the one the URL was generated for), disclosing deploy/task status (`stack.deploys_and_rollbacks.last`) for repositories the token holder was never granted access to. This matches the "High" impact category of unauthorized/unscoped read of stack state and deploy output.

### Likelihood Explanation
Trivial to exploit once any `read:stack` token is obtained (e.g. a leaked CCMenu URL, which is explicitly designed to be pasted into third-party CI-monitor tools and is not treated as highly sensitive by users) — the attacker only changes the `stack_id` route parameter. No additional session, App key, or elevated privilege is required beyond a token that already exists for legitimate, narrow purposes.

### Recommendation
In `Api::CCMenuController#stack`, use the base controller's scoped `stacks` relation (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!`, so a token's `stack_id` (when present) is enforced. Additionally, have `CCMenuUrlController#client` create/find the `ApiClient` scoped to the specific `stack` (pass `stack:` into `create_with`/`find_or_create_by!`, and key the lookup on `stack_id` as well as `creator`/`name`) so each generated CCMenu token is bound to exactly the stack it was issued for.

### Proof of Concept
1. As user A, visit `GET /stacks/:owner/:repo/:env/ccmenu_url` for stack `A` (`CCMenuUrlController#fetch`) to obtain a token via `client.authentication_token` — this creates/reuses an `ApiClient` named "CCMenu Client" with `permissions: ["read:stack"]` and no `stack_id`. [4](#0-3) 
2. Call the API endpoint with that token but substitute a different `stack_id` belonging to another repository/environment the attacker has no access to:
   `GET /api/stacks/:other_owner/:other_repo/:other_env/ccmenu.xml?token=<token>`
3. `Api::CCMenuController#authenticate_api_client` accepts the token (`ApiClient.authenticate(params[:token])`), `require_permission :read, :stack` passes because the token carries `read:stack`, and `#stack` resolves via unscoped `Stack.from_param!`, returning the other stack's deploy/task status in the response. [5](#0-4)

### Citations

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
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
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-18)
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
```
