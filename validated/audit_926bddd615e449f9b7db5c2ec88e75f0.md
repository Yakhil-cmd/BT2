### Title
Stack-scoped API token can read the build status of any stack via `CCMenuController` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController#stack` resolves the target stack directly from the unscoped `Stack` model instead of going through the `current_api_client`-scoped `stacks` collection that every other API controller uses. This breaks the binding between the set of stacks an `ApiClient` token is authorized for and the stack the action actually touches, letting a token that is scoped to a single stack read the deploy/build status of any other stack in the installation.

### Finding Description
`Shipit::Api::BaseController` enforces per-token stack scoping centrally: [1](#0-0) 

`require_permission` only checks that the token has the named permission string (e.g. `read:stack`); it never checks which stack the token is bound to: [2](#0-1) 

The scope binding (`current_api_client.stack_id`) is therefore enforced solely by the `stacks`/`stack` helper methods that every controller is expected to use, e.g.: [3](#0-2) 

`CCMenuController`, however, overrides `stack` to bypass that scoping entirely, resolving the stack from the global `Stack` relation using only the URL's `stack_id` param: [4](#0-3) 

It still declares `require_permission :read, :stack`, so any token carrying the `read:stack` permission string — including one deliberately restricted to a single stack via `ApiClient#stack_id` — passes the permission check, and then `stack` happily looks up an arbitrary stack requested in the path/params, independent of `current_api_client.stack_id`.

This is exactly the "stack a token authorizes" vs "stack it touches" binding called out as in-scope: the equality that should hold is `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id`, but `CCMenuController#stack` never checks it.

Shipit explicitly supports and creates such stack-scoped tokens, e.g. the `here_come_the_walrus` fixture (`stack: shipit_stacks(:shipit)`, permissions `['read:stack']`), and `StacksController` correctly honors that scope: [5](#0-4) 

`CCMenuUrlController` is the built-in mechanism that hands such tokens out to users/integrations as shareable "CCTray" URLs (query-string token, no session needed): [6](#0-5) [7](#0-6) 

### Impact Explanation
Any holder of a `read:stack`-scoped API token — even one intentionally minted for a single stack (e.g., a CCMenu/CI-monitor token) — can enumerate `stack_id` values and pull deploy/build status (`lastBuildStatus`, lock state, activity, last build label) for every stack hosted by the Shipit instance, not just the one it was issued for. This is an unauthenticated-scope read of stack state across repository/organization boundaries, which matches the "High — unauthenticated read of stack state" impact category, since the cross-stack read happens without the token ever being authorized for those other stacks.

### Likelihood Explanation
High. No privileged access, session, or additional secret is required beyond possessing any single valid stack-scoped `read:stack` token (which by design is distributed to third parties/CI dashboards via `CCMenuUrlController`). The attacker only needs to change the `stack_id` path parameter; `stack_id` values are small sequential/friendly identifiers, making enumeration trivial.

### Recommendation
Make `CCMenuController#stack` go through the scoped `stacks` collection (i.e., `stacks.from_param!(params[:stack_id])`) exactly as `BaseController#stack` and every other API controller do, so the `current_api_client.stack_id` restriction is honored for the CCMenu endpoint as well.

### Proof of Concept
1. As an admin, create (or let `CCMenuUrlController#fetch` create) an `ApiClient` scoped to Stack A with permissions `['read:stack']` (e.g. via the "CCMenu URL" feature on Stack A's page). Note the `token` in the resulting URL.
2. As an unprivileged holder of that token, request:
   `GET /api/stacks/<stack-B-id>/ccmenu.xml?token=<token-scoped-to-A>`
3. `CCMenuController#authenticate_api_client` authenticates the token successfully (`ApiClient.authenticate(params[:token])`), `require_permission :read, :stack` passes (token has `read:stack`), and `stack` resolves Stack B directly via `Stack.from_param!(params[:stack_id])`, returning Stack B's deploy/build status — despite the token only being authorized for Stack A.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L24-27)
```ruby
      before_action :authenticate_api_client

      def index
        render(json: { stacks_url: api_stacks_url })
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
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
