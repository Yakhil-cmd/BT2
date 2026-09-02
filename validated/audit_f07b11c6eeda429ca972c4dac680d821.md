### Title
CCMenu API endpoint lets a stack-scoped token read deploy status for any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` authenticates a request using an `ApiClient` token bound to a specific `stack_id`, but the stack it actually acts on is resolved from the unauthenticated `params[:stack_id]` without ever intersecting it with the client's assigned stack. This breaks the invariant "the stack a token authorises == the stack a token touches" that the `Api::BaseController` establishes for every other API controller.

### Finding Description
`Api::BaseController` enforces token-to-stack binding centrally: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the authenticated `ApiClient` is scoped to a single stack (`stack_id?` true), and `stack` resolves `params[:stack_id]` only from within that scoped relation. Every other API controller (`CommitsController`, `StacksController`, etc.) inherits and uses this `stack`/`stacks` method, so a stack-scoped token can never touch a stack outside its own.

`CCMenuController`, however, overrides both `authenticate_api_client` (to allow token in `params[:token]` instead of Basic Auth) and, critically, `stack`: [2](#0-1) 

Note `stack` here calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, bypassing the `stacks` method entirely. `require_permission :read, :stack` only checks that the `ApiClient#permissions` array contains `"read:stack"` — [3](#0-2)  — it never validates that the requested `stack_id` matches the client's own `belongs_to :stack` scope: [4](#0-3) .

The equality that should hold is: `current_api_client.stack_id (the stack the token was issued for) == stack.id (the stack whose data is returned)`. `CCMenuController#stack` breaks this by resolving `stack_id` from request params against the global `Stack` table instead of the client-scoped relation.

This mirrors the report's front-running/binding-mismatch bug class: a credential is checked for validity and for a coarse-grained capability ("read:stack" in general) but a fine-grained binding field (which specific stack) present in the request is never cross-checked against the value baked into the credential — exactly like the SGX report's `signer` being bound to whichever `msg.sender` called `register`, rather than to the custodian embedded in the signed report.

### Impact Explanation
A CCMenu token minted for one stack — via `Shipit::CcmenuUrlController#fetch`, which builds a URL of the form `.../ccmenu/<stack_id>?token=<token>` — can be replayed by substituting an arbitrary `stack_id` in the URL/query params. Since `CCMenuController#stack` never checks `current_api_client.stack_id`, the request succeeds for any stack in the Shipit installation, exposing:
- stack name, lock state, latest deploy/rollback id, status and build time (`app/views/shipit/ccmenu/project.xml.builder`, `Api::CCMenuController#show`).

This is an authorization escalation: a token meant to be confined to a single stack gains read access to deploy status/state of every other stack managed by the installation — matching the rules' High-impact category of "escalation into `Shipit.github_teams` authorization" / "unauthenticated [cross-boundary] read of stack state ... or deploy output" relative to what the credential was actually scoped for.

### Likelihood Explanation
Any holder of a legitimately-issued, stack-scoped CCMenu token (e.g., a contributor with `read:stack` access to only one project/stack, or anyone who obtains a leaked CCMenu URL for a low-sensitivity stack) can trivially exploit this by changing the `stack_id` path/query parameter — no additional privileges, secrets, or code execution required. The endpoint is unauthenticated aside from the token itself (`get_project_from_xml`/no session needed), so this is directly reachable by an unprivileged holder of any valid CCMenu token.

### Recommendation
In `Api::CCMenuController`, remove the private `stack` override (or reimplement it to reuse the inherited scoping) so that it resolves the stack through the same `stacks` relation as `Api::BaseController#stack`:

```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

This ensures `Stack.where(id: current_api_client.stack_id)` scoping (when the client is stack-bound) is enforced identically to every other API endpoint, restoring the `token-authorized-stack == accessed-stack` invariant.

### Proof of Concept
1. As a legitimate user with access to Stack A only, visit `/ccmenu_url/<stack_a_id>` to obtain a CCMenu URL: `GET /api/<stack_a_id>/ccmenu?token=<TOKEN>` where `TOKEN` is minted via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, ...)` and is (in the general `ApiClient` model) or could be configured to be `belongs_to :stack` scoped to Stack A only.
2. Take that same `TOKEN` and issue: `GET /api/<stack_b_id>/ccmenu?token=<TOKEN>` for Stack B, an unrelated stack the token was never authorized for.
3. Observe HTTP 200 with Stack B's deploy status/build info rendered, because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` (`app/controllers/shipit/api/ccmenu_controller.rb:29-31`) instead of the client-scoped `stacks.from_param!` used by `Api::BaseController#stack` (`app/controllers/shipit/api/base_controller.rb:78-80`), so the `stack_id?` scoping check in `Api::BaseController#stacks` (`base_controller.rb:74-76`) is never applied.

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

**File:** app/models/shipit/api_client.rb (L1-12)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
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
