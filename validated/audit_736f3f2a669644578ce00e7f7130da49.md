### Title
CCMenu tokens are not scoped to the requesting stack, allowing cross-stack read of deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The CCMenu integration issues a `read:stack` `ApiClient` token per-stack for use in unauthenticated third-party CI dashboards, but that token is never bound to the stack it was minted for. `Api::CCMenuController` then authorizes purely on the `read:stack` permission and resolves the target stack straight from the URL parameter, so the same token can be replayed against any stack in the installation.

### Finding Description
`CCMenuUrlController#client` mints an `ApiClient` scoped only by permission, with no `stack:` binding: [1](#0-0) 

Compare this with `ApiClient`, which does support per-client stack scoping (`belongs_to :stack, optional: true`), and `Api::BaseController#stacks`, which correctly restricts a client's visible stacks to `current_api_client.stack_id` when it is set: [2](#0-1) [3](#0-2) 

`Api::CCMenuController`, however, never goes through that `stacks` scoping helper. It authenticates the token via a custom override and resolves the stack directly from the request parameter: [4](#0-3) 

`require_permission :read, :stack` only calls `ApiClient#check_permissions!`, which checks the string `"read:stack"` is present in `permissions` — it has no notion of *which* stack: [5](#0-4) 

The equality that should hold is: `stack the token was issued for == stack the request operates on`. Because the `ApiClient` created in `CCMenuUrlController#client` leaves `stack_id` nil, and `Api::CCMenuController#stack` never checks `current_api_client.stack_id` against `params[:stack_id]`, that equality is never enforced. A token minted for one stack's public CCMenu badge is functionally a global `read:stack` credential.

### Impact Explanation
This crosses the "a stack a token authorises versus a stack it touches" trust boundary. CCMenu URLs are explicitly designed to be handed to unauthenticated, external CI-status aggregators/widgets (this is the entire purpose of `CCMenuUrlController`, which returns a URL with `token` in the query string for a specific stack). Anyone who obtains one such URL — a low-privilege team member, a viewer of an embedded status badge, or anyone the URL was shared with — can swap `stack_id` in the path to read the live deploy status (last deploy id, running state, timestamps) of every other stack managed by that Shipit instance, including stacks/repositories they have no legitimate visibility into. This matches the High-severity bucket: "unauthenticated read of stack state ... or deploy output."

### Likelihood Explanation
Likelihood is high: no special privilege is required beyond having been given (or having discovered) a single CCMenu token for any one stack — a token that is designed to be embedded in unauthenticated tooling and is therefore inherently exposed outside the Shipit session/authentication boundary. Exploitation is a single unauthenticated GET request substituting a different `stack_id`.

### Recommendation
Bind the `ApiClient` created in `CCMenuUrlController#client` to the specific stack (`stack: stack`), and enforce that binding in `Api::CCMenuController#stack` (e.g., raise/`not_found` unless `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id`), mirroring the scoping already applied by `Api::BaseController#stacks`.

### Proof of Concept
1. A user with access to `stack-A` visits its settings page, triggering `GET /stack-A/ccmenu_url` → `CCMenuUrlController#fetch` creates an `ApiClient` with `permissions: ["read:stack"]` and no `stack_id`, returning a URL like `/api/stack-A/ccmenu.xml?token=T`.
2. `T` is exposed to any unauthenticated consumer of that CCMenu URL (e.g., embedded in a public build-status widget or otherwise shared, per the feature's design).
3. Anyone holding `T` requests `GET /api/stack-B/ccmenu.xml?token=T` for an unrelated, private `stack-B`.
4. `Api::CCMenuController#authenticate_api_client` verifies `T` successfully (`ApiClient.authenticate`), `require_permission :read, :stack` passes because the token has `read:stack`, and `stack` resolves to `Stack.from_param!("stack-B")` — the response discloses `stack-B`'s deploy status even though `T` was only ever issued for `stack-A`.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/models/shipit/api_client.rb (L1-8)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-36)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```
