### Title
CCMenu API token issued for one stack grants unauthenticated read access to every stack's deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` looks up the target `Stack` directly from the `stack_id` URL parameter instead of going through the tenant-scoping logic used everywhere else in the API (`Api::BaseController#stacks`/`#stack`), and the `ApiClient` used to mint the CCMenu token is never bound to the specific stack it was requested for. This breaks the binding "the stack a CCMenu token is meant to authorize" versus "the stack whose data it actually returns", which is the same class of trust-binding gap as the report's TokenManager missing-allowance-check bug (a control that is supposed to gate access to a specific resource is never actually enforced for that resource).

### Finding Description
`Api::BaseController` restricts stack access to the token's own stack when one is set: [1](#0-0) 

`Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely and resolve the stack straight from client-supplied `params[:stack_id]` across **all** stacks: [2](#0-1) 

It also authenticates using a bare `params[:token]` lookup rather than the standard Basic-Auth flow: [3](#0-2) 

Worse, the token itself is never bound to a specific stack at issuance time. `Shipit::CcmenuUrlController#client` mints (or reuses) a single `ApiClient` per `creator`+name only, without setting `stack:`, regardless of which stack's CCMenu URL was requested: [4](#0-3) 

Because `ApiClient#stack_id` stays `nil` for this shared "CCMenu Client", `Api::BaseController#stacks` would already treat it as unscoped (`Stack.all`) even without the `CCMenuController#stack` override — the override simply removes the last theoretical layer of protection. The only gate left is `require_permission :read, :stack`, which checks that the token carries the `read:stack` permission string, not which stack it is permitted to touch: [5](#0-4) [6](#0-5) 

**Binding broken (equality that should hold but doesn't):**
`stack authorized by the CCMenu token at issuance` ⟺ `stack whose deploy status the token can read`
Before a fix: the left side is "any single stack the URL was generated for"; the right side is "every stack in the Shipit instance". These are not equal, exactly mirroring the report's `allowance(capitalPool, TokenManager)` vs `amount actually withdrawn` binding failure — a check exists in name (`require_permission :read, :stack`) but never verifies the scope claimed by the resource path.

### Impact Explanation
CCMenu/CCTray URLs are explicitly designed to be embedded in low-trust contexts (CI dashboard tools, IRC bots, browser widgets) and are handed out per-stack from the UI. Because the underlying token is unscoped, any leak of a single stack's `ccmenu_url` (a URL considered "safe to share" for a specific project) lets the holder enumerate `stack_id` and read the deploy/build status, last deploy outcome, and stack existence for every stack managed by that Shipit instance — an unauthenticated read of stack state performed with credentials the victim believed were limited to one project. This matches the "High - unauthenticated read of stack state" impact category.

### Likelihood Explanation
Likelihood is high once any single CCMenu URL is exposed (which is the intended, expected use case for this feature — embedding in dashboards, CI status widgets, etc.). No repository write access, webhook secret, GitHub App key, or privileged Shipit session is needed beyond the one leaked token; the attacker only needs to change the `stack_id` query parameter to enumerate other stacks' data.

### Recommendation
- Bind `ApiClient#stack` to the specific stack at creation time in `CcmenuUrlController#client` (include `stack:` in the `find_or_create_by!` lookup/creation attributes, not just `creator`/`name`).
- Remove the `Api::CCMenuController#stack` override and use the inherited, scope-respecting `stacks.from_param!(params[:stack_id])` from `Api::BaseController` so a token's `stack_id` is always enforced.

### Proof of Concept
1. As User A, visit stack "alpha" and load its CCMenu URL via `GET /stacks/alpha/production/ccmenu_url`, obtaining `token=T`.
2. `GET /api/ccmenu?stack_id=alpha-production&token=T` succeeds and returns alpha's status (expected).
3. Without any further authorization, request `GET /api/ccmenu?stack_id=beta-production&token=T` for an unrelated stack "beta" that User A has no relationship to.
4. Because `ApiClient` `T` has `stack_id == nil` and `CCMenuController#stack` never checks it, the request succeeds and returns beta's deploy status — data the token was never meant to expose.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-12)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack

      class NoDeploy
        def id
          0
        end

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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
