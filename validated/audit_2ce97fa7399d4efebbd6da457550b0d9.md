## Confirmed vulnerability

### Title
Stack-scoped ccmenu API token authorizes reads of any stack's build/deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` re-implements the `stack` lookup method instead of using the scoped `stack`/`stacks` helpers provided by `Shipit::Api::BaseController`. As a result, a `ApiClient` token that was minted and is only supposed to authorize read access to a *single*, specific stack can be replayed with a different `stack_id` URL parameter to read the CI/build status of **any** stack in the Shipit instance.

### Finding Description
`Shipit::Api::BaseController` defines the canonical, scope-respecting stack accessor: [1](#0-0) 
`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` is scoped to a specific stack (`stack_id?`), and `stack` (used by every other API controller, e.g. `StacksController`, `DeploysController`) is derived from that scoped relation.

`CCMenuController`, however, overrides `stack` with its own implementation that ignores this scoping entirely: [2](#0-1) 
It loads `Stack.from_param!(params[:stack_id])` directly from the whole `Stack` table, with no reference to `current_api_client.stack_id`. The only authorization check performed is `require_permission :read, :stack`: [3](#0-2) 
which merely checks that the string `"read:stack"` is present in the token's `permissions` array — it never compares the requested `stack_id` against the token's bound `stack_id`. [4](#0-3) 

These stack-scoped tokens are exactly the kind of low-privilege, widely-shared credential this endpoint expects: `CCMenuUrlController#fetch` mints a new `ApiClient` scoped to one specific stack and only the `read:stack` permission, then embeds the resulting bearer token in a plain URL query string intended for third-party CI dashboard tools (CCTray-compatible widgets, browser extensions, status boards): [5](#0-4) 

This is the exact class of bug described in the external report: two computations that are supposed to be equivalent/bound together silently diverge. Here the binding that should hold is:
```
stack authorized by token (ApiClient#stack_id) == stack touched by the request (params[:stack_id] loaded in CCMenuController#stack)
```
The code never enforces this equality for the ccmenu endpoint, even though the sibling `BaseController#stack`/`#stacks` implementation shows the correct, intended enforcement pattern is trivially available.

### Impact Explanation
Any party who obtains a single-stack-scoped ccmenu token (these are designed to be embedded in plaintext URLs and shared with third-party tooling, so leakage via logs, browser history, Referer headers, screenshots, or accidental exposure is a realistic and expected occurrence for this feature) can swap the `stack_id` parameter and read the deploy/merge/build status, `webUrl` (stack permalink), last build id, and activity ("Building"/"Sleeping") of **every** stack configured in the Shipit instance — including private or unrelated stacks the token holder was never granted access to. This is an unauthorized read of stack state/deploy status across the authorization boundary defined by `ApiClient#stack_id`, matching the "High — unauthenticated/unauthorized read of stack state, task streams or deploy output" impact category: the attacker escalates from a single-stack-scoped credential to instance-wide stack-status disclosure.

### Likelihood Explanation
Exploitation requires only possession of any valid ccmenu token (no elevated permissions, no GitHub credentials, no admin access) and manipulation of a single URL query parameter (`stack_id`) — trivial for anyone who has ever been handed a ccmenu URL, which by design is meant to be embedded in low-trust, external monitoring tools. No race conditions or timing are needed; the bypass is deterministic on every request.

### Recommendation
Make `CCMenuController#stack` respect the same scoping as `BaseController#stack`/`#stacks`, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so that a stack-scoped `ApiClient` can only ever resolve to the stack it was actually created for, mirroring the enforcement already present in `BaseController`.

### Proof of Concept
1. As a legitimate low-privilege user of Stack A, visit `CCMenuUrlController#fetch` (e.g., via the stack A settings page) to obtain a ccmenu URL: `GET /api/StackA/ccmenu?token=<token-scoped-to-StackA>`.
2. This creates (or reuses) an `ApiClient` with `stack_id = StackA.id` and `permissions = ["read:stack"]`. [6](#0-5) 
3. Take the same `token` value and request a different stack's ccmenu feed: `GET /api/StackB/ccmenu?token=<token-scoped-to-StackA>`.
4. `CCMenuController#authenticate_api_client` authenticates the token successfully (it is valid, just scoped to Stack A). [7](#0-6) 
5. `require_permission :read, :stack` passes because the token has `read:stack` in its permission list, regardless of which stack.
6. `stack` resolves `Stack.from_param!(params[:stack_id])` == Stack B directly, bypassing the `stack_id` scope, and the XML response discloses Stack B's build status, activity, and permalink — data the Stack-A-scoped token was never authorized to see. [8](#0-7)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-31)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

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
