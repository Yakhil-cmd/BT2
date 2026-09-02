### Title
API token stack-scope bypass in `Api::CCMenuController#stack` — unauthorized cross-stack read of build/deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` enforces a binding between an `ApiClient`'s `stack_id` and the stacks it is allowed to touch: when an `ApiClient` is scoped to a specific stack, `stacks` (and therefore `stack`) is restricted to `Stack.where(id: current_api_client.stack_id)` [1](#0-0) . `Api::CCMenuController`, however, overrides `stack` to resolve unconditionally against the full `Stack` table via `Stack.from_param!(params[:stack_id])`, never consulting `current_api_client.stack_id` [2](#0-1) . The controller still relies on `require_permission :read, :stack` [3](#0-2) , which only checks that the `read:stack` permission string is present on the token — it does not verify the requested `stack_id` matches the token's bound stack.

### Finding Description
The equality that should hold for every API endpoint is:
`stack the ApiClient is authorized for == stack the ApiClient can act on (or read)`.

`BaseController#stacks`/`#stack` implement this by intersecting the `Stack` scope with `current_api_client.stack_id` when the client is stack-scoped [1](#0-0) . `CCMenuController` breaks this equality: its `authenticate_api_client` accepts a token via the `token` query parameter (`ApiClient.authenticate(params[:token])`) [4](#0-3) , and its `stack` method resolves `params[:stack_id]` against *all* stacks, not the client's scoped stack [2](#0-1) .

`ApiClient#check_permissions!` only checks that the permission string (`read:stack`) is included in the client's permission list; it has no knowledge of which stack is being requested [5](#0-4) . So a token created with `permissions: %w[read:stack]` and a specific `stack_id` — exactly the kind of token minted by `CCMenuUrlController` for embedding in external CI dashboards [6](#0-5)  — passes `require_permission :read, :stack` for *any* `stack_id` value supplied in the request, not just the one it was minted for.

Before the crafted request: token T is (or is intended to be) bound to stack A, permission `read:stack`, exposed via a CCMenu URL (a URL pattern designed to be embedded in third-party CI aggregation tools, i.e., handed to less-trusted consumers than the full Shipit UI).
After the crafted request: the same token T, with `stack_id=B` substituted in the URL, returns full CCMenu XML status (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, `activity`, etc.) for stack B, an arbitrary stack the token was never scoped to.

### Impact Explanation
This meets the High-severity bar of "unauthenticated read of stack state / deploy output" in effect: possession of any single stack-scoped `read:stack` CCMenu token becomes equivalent to an instance-wide `read:stack` token because the `stack_id` scoping is never enforced in this endpoint. Since CCMenu URLs are specifically designed to be handed off to third-party status-badge/CI-dashboard integrations (a lower trust boundary than the main Shipit UI/API), leakage of one such URL — which is expected to happen since it's meant for external consumption — discloses build/deploy status of every stack in the Shipit instance, including stacks belonging to unrelated repositories/teams.

### Likelihood Explanation
High. No privileged action or special access is required beyond possessing any existing, otherwise-legitimate stack-scoped CCMenu token (which by design is meant to be shared with external tooling). The attacker only needs to know or guess another stack's `stack_id` (an easily discoverable owner/repo/environment path segment) and substitute it into the URL.

### Recommendation
In `Api::CCMenuController#stack`, resolve the stack through the same scoped lookup as `BaseController`:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
reusing (not overriding) `BaseController#stacks`, so that `current_api_client.stack_id` scoping is enforced identically to every other API endpoint.

### Proof of Concept
1. Admin creates (or a user self-provisions via `CCMenuUrlController#fetch`) a `read:stack`-permissioned `ApiClient` scoped to Stack A (`stack_id = A`), and shares the resulting CCMenu URL, e.g. `https://shipit.example.com/api/orgA/repoA/production/ccmenu.xml?token=<A-token>` (see token minting logic) [7](#0-6) .
2. Attacker (any party who obtained this URL, e.g. from a public CI dashboard config) sends:
   `GET /api/orgB/repoB/staging/ccmenu.xml?token=<A-token>`
3. `authenticate_api_client` authenticates `<A-token>` successfully (valid signature) [4](#0-3) ; `require_permission :read, :stack` passes because the token has `read:stack` [5](#0-4) ; `stack` resolves Stack B via unscoped `Stack.from_param!` [2](#0-1) .
4. The response discloses Stack B's build/deploy status (`show` action) [8](#0-7) , despite the token never having been authorized for Stack B.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L20-25)
```ruby
      end

      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-32)
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
