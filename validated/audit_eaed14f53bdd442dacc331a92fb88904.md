### Title
`Api::CCMenuController#stack` bypasses the ApiClient's stack scope, letting a stack-scoped token read any stack's CCMenu status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
This is an analog of the reported "check performed against one entity, action performed against another" bug class: the `RewardsDistributor#claim` bug checked/covered the wrong token/lock relationship. In `shipit-engine`, `Api::BaseController` establishes an equality that every API-authorized `ApiClient` token is bound to a specific stack scope: `stack_id_permitted_by_token == stack_id_acted_on`. `Api::CCMenuController` breaks this equality by overriding `stack` to load an arbitrary `params[:stack_id]` instead of using the scoped `stacks` relation.

### Finding Description
`Api::BaseController` defines the scoping invariant used by every other API controller: [1](#0-0) 

`stacks` is restricted to `current_api_client.stack_id` when the client is scoped to a stack, and `stack` looks up `params[:stack_id]` only within that restricted relation. This is exactly the mechanism the `CCMenuUrlController` relies on when it mints a token: it creates a `read:stack` `ApiClient` and expects that token to only ever be usable for the specific `stack_id` embedded in the generated CCMenu URL. [2](#0-1) 

However, `Api::CCMenuController` overrides `stack` and does not use the `stacks` scoping helper at all - it loads any stack directly from `Stack.from_param!(params[:stack_id])`: [3](#0-2) 

`require_permission :read, :stack` only checks that the token carries the `read:stack` permission string; it never checks that the requested stack matches `current_api_client.stack_id`: [4](#0-3) [5](#0-4) [6](#0-5) 

The route itself takes an arbitrary `stack_id` segment, confirming the attacker-controlled input surface: [7](#0-6) 

**Equality broken:** `stack the token is scoped to (ApiClient#stack_id) == stack the request actually touches (params[:stack_id] via Stack.from_param!)`. Before the flaw is exploited, every other API controller enforces this equality via `BaseController#stack`/`#stacks`; `CCMenuController` is the outlier that silently drops the scoping and only re-checks the coarse `read:stack` permission string, not stack identity.

### Impact Explanation
A holder of any `read:stack`-permissioned `ApiClient` token that is scoped to Stack A (e.g. the token minted by `CCMenuUrlController` for a single stack, or any other token an operator restricted to one stack for least-privilege reasons) can supply a different `stack_id` in the URL and read the CCMenu XML status (last build status/label/time, activity, running state) for Stack B, which they were never authorized to see. This is an unauthenticated-for-that-resource read of stack state via a token whose entire purpose was to be limited to one stack — matching the "High: unauthenticated read of stack state" impact class, since the token's authorization scope for that other stack is effectively bypassed.

### Likelihood Explanation
Any party who obtains a stack-scoped `read:stack` token (which by design is meant to be low-privilege and is even embedded directly in a URL sent to third-party CI-monitoring tools by `CCMenuUrlController`) can trivially exploit this by changing the `stack_id` path segment — no additional secrets, signatures, or privileges are required beyond having that single-stack token, which is the intended low-trust use case for this endpoint.

### Recommendation
Make `Api::CCMenuController#stack` use the same scoped lookup as the rest of the API (`stacks.from_param!(params[:stack_id])` from `BaseController`) instead of `Stack.from_param!(params[:stack_id])`, so the token's `stack_id` scope is enforced consistently across all API controllers.

### Proof of Concept
1. Operator uses `CCMenuUrlController#fetch` (or `ApiClient` admin UI) to mint a `read:stack` token scoped to Stack A (`stack_id` set) — e.g. `ApiClient.create!(stack: stack_a, permissions: ['read:stack'])`.
2. Attacker (or the third-party CI dashboard given that URL) takes the resulting token and calls:
   `GET /api/stacks/<stack_b_owner>/<stack_b_repo>/<stack_b_env>/ccmenu?token=<stack_a_token>`
3. `authenticate_api_client` succeeds because the token is valid; `require_permission :read, :stack` passes because the token has `read:stack`.
4. `stack` resolves `Stack.from_param!(params[:stack_id])` directly to Stack B, ignoring that the token's `stack_id` is Stack A.
5. Response renders Stack B's CCMenu XML (deploy status, activity, last build label/time), which the token was never authorized to access.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L18-22)
```ruby
      class << self
        def require_permission(operation, scope, options = {})
          before_action(options) { require_permission!(operation, scope) }
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

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
```
