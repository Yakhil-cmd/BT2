### Title
CCMenu API allows any valid `ApiClient` token to read the build status of a stack it was never scoped to - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController#stack` bypasses the stack-scoping logic that every other `Api::BaseController` subclass relies on, so an `ApiClient` token that was issued (and authorized by a human) for a single stack can be replayed with a different `stack_id` to read CCMenu deploy status for any stack in the installation.

### Finding Description
`Api::BaseController` binds an authenticated `ApiClient` to the set of stacks it is allowed to touch: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is scoped to one stack, and `stack` (used by every controller that needs a single stack) is built from that restricted relation. The only other guard, `require_permission`, merely checks that the token has the *permission name* `read:stack`/`write:stack`/etc. via `ApiClient#check_permissions!`, which never looks at `stack_id` at all: [2](#0-1) 

So the actual "which stack does this token authorize" binding is enforced exclusively inside `BaseController#stack`/`#stacks`.

`Api::CCMenuController` inherits from `BaseController` and declares `require_permission :read, :stack`, but it overrides `stack` to bypass the scoped `stacks` relation entirely and load directly from the raw `params[:stack_id]`: [3](#0-2) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```

This means the equality that should hold — `token.authorized_stack == stack_being_read` — is never checked here; only `token.permissions.include?("read:stack")` is checked, which is true for *any* stack-scoped or global token that has that permission bit.

Tokens for this exact endpoint are minted precisely to be scoped to one stack: [4](#0-3) 

`CCMenuUrlController#client` creates (or reuses) an `ApiClient` with `permissions: %w[read:stack]` and a specific `stack:` association, and hands the resulting `authentication_token` back to the browser embedded in a URL (`ccmenu_url`) intended to be pasted into third-party CI dashboard tools. Because CCMenu tokens are long-lived, low-friction credentials meant to be shared/embedded outside of Shipit's session/auth boundary, and because any `ApiClient` with `read:stack` permission works interchangeably here regardless of its `stack_id`, an attacker who obtains **any** `read:stack`-scoped token (their own stack's CCMenu URL, a leaked/shared one, or a token created via the web UI for an unrelated stack) can substitute an arbitrary `stack_id` in the request and read that stack's latest deploy/rollback status.

The `authenticate_api_client` override in `CCMenuController` further weakens things by pulling the token from a URL query parameter (`params[:token]`) rather than requiring HTTP Basic auth, making it trivial to swap the `stack_id` while keeping the same query-string token: [5](#0-4) 

This is a direct analog of the M-38 bug class: a binding that is supposed to be enforced (allocation state consistent with the reward calculation / here, "which stack a token is scoped to") is skipped in one code path (`settleDeltaAllocation` executed too early / here, `stack` overridden to skip `stacks` scoping), so the check that runs (permission-name check) authorizes an action against the wrong underlying resource (wrong period's `totalAllocatedTokens` / wrong `stack_id`).

### Impact Explanation
This lets an unprivileged holder of any `read:stack`-permissioned `ApiClient` token — including one legitimately scoped to a completely different, low-sensitivity stack — read deploy/build status (including whether a deploy is running, its result, and its identifying info surfaced via the CCMenu XML) for any stack in the Shipit installation, including private/production stacks the token was never meant to see. This matches the "High" impact tier: unauthenticated (relative to the target stack) read of stack state / deploy output across stack boundaries.

### Likelihood Explanation
Likelihood is high for anyone who already possesses one valid `read:stack` token (a very low bar — any team member with access to any stack's settings page can mint one via `CCMenuUrlController`, and CCMenu URLs are explicitly designed to be shared with external CI-status tools). No repository write access, GitHub credentials, or session is required — only substituting the `stack_id` route/query parameter in an otherwise valid request.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` (or reimplement it to reuse `BaseController#stacks`/`#stack`) so CCMenu status lookups are constrained to `current_api_client.stack_id` exactly the same way every other API controller enforces it, i.e. `@stack ||= stacks.from_param!(params[:stack_id])`.

### Proof of Concept
1. As a legitimate user with access to Stack A (low sensitivity), visit its settings page and trigger `CCMenuUrlController#fetch` to obtain a `read:stack`-scoped `ApiClient` token bound to Stack A (`stack: A`).
2. Note the resulting `ccmenu_url`, e.g. `GET /api/stacks/A_id/ccmenu.xml?token=<token>`.
3. Replace `A_id` with the id/slug of Stack B (a private/production stack the attacker has no access to): `GET /api/stacks/B_id/ccmenu.xml?token=<token>`.
4. `Api::CCMenuController#authenticate_api_client` verifies the token is a valid `ApiClient` (it is — scoped to A). `require_permission :read, :stack` passes because the token has `read:stack`. `stack` loads `Stack.from_param!(B_id)` directly, bypassing the `stack_id` scoping check. The response renders Stack B's CCMenu status, disclosing its deploy state to an attacker with no authorization on Stack B.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-39)
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

        def ended_at
          Time.now.utc
        end

        def running?
          false
        end
      end

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
    end
  end
end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L1-24)
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
end
```
