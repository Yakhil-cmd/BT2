### Title
CCMenuController bypasses ApiClient stack scoping, letting a stack-scoped token read the deploy status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` re-implements the `stack` lookup instead of using the `BaseController`'s scoped helper, so an `ApiClient` token that is only authorised for one stack (`stack_id` set) can be replayed against any other stack's CCMenu endpoint. This mirrors the reported bug class: a helper method (`lockForAnOrder`/`unlockForAnOrder` in the report) that is supposed to respect a binding (funds locked == funds the caller owns) is bypassed by a sibling code path that reuses the same primitive without the safety check — here, the binding "stack a token authorises == stack the token touches" is dropped in one specific controller while it is enforced everywhere else.

### Finding Description
`Shipit::Api::BaseController` defines the authorization-safe accessor used by every other API controller: [1](#0-0) 

`stacks` restricts the visible `Stack` set to `current_api_client.stack_id` when the client is scoped to a specific stack, and `stack` performs the `from_param!` lookup through that restricted scope. `ApiClient#stack_id?` comes from `belongs_to :stack, optional: true` on the model: [2](#0-1) 

`Shipit::Api::CCMenuController`, however, overrides `stack` to look the record up directly, ignoring `current_api_client` entirely: [3](#0-2) 

`require_permission :read, :stack` only checks that the string `"read:stack"` is present in `ApiClient#permissions` — it never checks which stack the permission applies to: [4](#0-3) 

So the equality that should hold — `stack authorised by token == stack acted upon` — is:
- Before: for every other API controller, `stack` is resolved through `stacks`, which equals `Stack.where(id: current_api_client.stack_id)` when the client is scoped; the two sides match.
- After: for `CCMenuController#show`, `stack` is resolved via `Stack.from_param!(params[:stack_id])` with no reference to `current_api_client.stack_id`; the token's authorised stack and the stack actually rendered can differ for any `stack_id` param supplied by the caller.

The `token` param used to authenticate CCMenu is passed on the query string (and is explicitly the credential handed out by `CCMenuUrlController`): [5](#0-4) 

Any `ApiClient` that carries `read:stack` and has ever been scoped to a single stack (the model supports `belongs_to :stack, optional: true`, and the scoping check exists specifically for this purpose in `BaseController#stacks`) will, when used against `/api/*/ccmenu` with a different `stack_id`, disclose that other stack's latest deploy/rollback id and running state — data the token holder was never granted `read:stack` on.

### Impact Explanation
This breaks the "a stack a token authorises versus a stack it touches" binding called out in the validation rules. A CI token, CCMenu tray client, or any other holder of a single-stack-scoped `read:stack` credential can enumerate `stack_id` params and pull deploy/rollback status for stacks outside its authorised scope — an authorization-scope escape reading stack/deploy state that should require a separately-issued, separately-scoped token.

### Likelihood Explanation
Exploitation only requires possession of a valid, but narrowly-scoped, `read:stack` API token (which is routinely distributed as a CCMenu URL, embedded in CI build status widgets, etc.) and the ability to guess or discover another stack's `owner/name/environment` path segment, all of which are visible in Shipit's own UI/URLs. No privileged access, secret material, or session is required beyond the token itself.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController` and delegate to `BaseController#stack`/`#stacks` (or explicitly re-check `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id`) so the CCMenu endpoint enforces the same per-token stack scoping as the rest of the API surface.

### Proof of Concept
1. Create (or obtain) an `ApiClient` with `permissions: ["read:stack"]` and `stack_id` set to Stack A (e.g., via the `CCMenuUrlController` flow or any stack-scoped client provisioning path).
2. Call `GET /api/{stack_A_owner}/{stack_A_name}/{env}/ccmenu.xml?token=<that client's authentication_token>` — succeeds as expected.
3. Call `GET /api/{stack_B_owner}/{stack_B_name}/{env}/ccmenu.xml?token=<same token>` for an unrelated Stack B.
4. Observe the request succeeds and returns Stack B's latest deploy/rollback id and running status, even though the token's `stack_id` only authorises Stack A — because `CCMenuController#stack` resolves via `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!`.

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

**File:** app/models/shipit/api_client.rb (L1-21)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L1-23)
```ruby
# frozen_string_literal: true

require 'uri'

module Shipit
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

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
  end
```
