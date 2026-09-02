### Title
CCMenu API client tokens are minted without a `stack_id` scope, granting unscoped `read:stack` access to all stacks - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`CCMenuUrlController#client` mints an `ApiClient` token for the currently authenticated user without ever setting the `stack` association, so the token's authorization scope (all stacks) diverges from the single stack the UI flow intends to expose. This breaks the "stack a token authorises" == "stack it is meant to touch" binding described in the report's core bug class (a permission granted at one granularity being enforced at another, broader, granularity).

### Finding Description
The equality that should hold is: `stack a token is scoped to` == `stack the UI flow that created it intended to expose`. `CCMenuUrlController#fetch` builds a CCMenu URL for one specific `stack` (resolved from `params[:stack_id]`) and attaches a freshly minted API token to it: [1](#0-0) 

The `client` method creates (or finds) the `ApiClient` using only `creator` and `name` as the lookup/creation keys, and grants it the `read:stack` permission - but never assigns `stack:` to scope it to the requested stack: [2](#0-1) 

`ApiClient` supports an optional `belongs_to :stack, optional: true` association specifically to scope a token's visibility: [3](#0-2) 

The API layer enforces that scoping via `stack_id?`: when an `ApiClient` has no `stack_id`, every `Stack` in the installation is visible to it: [4](#0-3) 

Because `find_or_create_by!(creator: current_user, name: 'CCMenu Client')` does not include `stack:`, the very first time a user requests a CCMenu URL for *any* stack, a single unscoped "CCMenu Client" `ApiClient` is created for that user with `read:stack` permission and no `stack_id`. Every subsequent call to `fetch` for *any other stack* (including ones this record was never explicitly created for) finds and reuses that same unscoped client (since `stack` isn't part of the lookup), and hands the user a token URL that is valid for the entirely different intended stack, while the underlying token actually authorizes reading **every** stack via the API (`GET /stacks`, `GET /stacks/:id`, etc.), not just the one whose `stack_id` appears in the CCMenu URL.

### Impact Explanation
This is an escalation from "read access to one stack via a generated CCMenu monitor URL" to "unauthenticated (bearer-token-only) read access to the state of every stack in the Shipit installation," including stacks/deploy output the user was never granted UI access to review via this flow. `CCMenuController` only requires `read:stack` permission and resolves stacks through the unscoped `stacks` relation, so the token can be used against `Api::StacksController#index`/`#show` and `Api::CcmenuController#show` for arbitrary stack IDs. This matches the report's "High" bucket: unauthenticated read of stack state/task streams via a broken authorization scope, mirroring the underlying SpinLottery bug class where the enforced allocation (locked prizes / here, token scope) did not match the intended, narrower allocation (weighted prize distribution / here, single-stack scope).

### Likelihood Explanation
Medium-High. No special privilege is required beyond the ability to view one stack in the UI (any authenticated, `Shipit.github_teams`-authorized user) and click "get CCMenu URL," a normal, low-friction feature. The bug is deterministic (not probabilistic like the original finding) — it fires on the very first CCMenu URL request for any user, and persists for the account thereafter.

### Recommendation
Scope the `ApiClient` lookup/creation to the requested stack, e.g. `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, stack: stack, name: 'CCMenu Client')`, so each stack gets its own token limited via `current_api_client.stack_id?` to that single stack, restoring the intended `token scope == exposed stack` binding.

### Proof of Concept
1. As an authorized Shipit user with access to only `stack-A`, visit `stack-A`'s page and trigger the "Get CCMenu URL" action, hitting `CCMenuUrlController#fetch` for `stack-A`.
2. `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` creates a new `ApiClient` row with `creator_id = current_user.id`, `permissions = ['read:stack']`, and `stack_id = nil` (never set). [2](#0-1) 
3. The returned token (`client.authentication_token`) is embedded in the CCMenu URL for `stack-A`, but because `stack_id` is `nil`, `current_api_client.stack_id?` is `false`.
4. Use that same bearer token against `GET /stacks` (`Api::StacksController#index`) or `GET /stacks/:id/ccmenu.xml` for `stack-B` (a stack the user has no legitimate reason to monitor via this flow): `stacks` resolves to `Stack.all` per `base_controller.rb:75`, so the request succeeds and returns `stack-B`'s state/deploy data — a stack whose authorization boundary was never intended to be crossed by a token minted for `stack-A`. [4](#0-3)

### Citations

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

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```
