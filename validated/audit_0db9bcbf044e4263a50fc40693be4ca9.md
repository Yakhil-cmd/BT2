## Title
CCMenuController bypasses ApiClient stack scoping, allowing a stack-scoped API token to read any stack's CI/deploy status - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::ApiClient` supports being scoped to a single stack via its optional `belongs_to :stack` association (confirmed by fixture `here_come_the_walrus`, which sets `stack: shipit` and `permissions: [read:stack]`) [1](#0-0) [2](#0-1) . `Api::BaseController` enforces this binding centrally: `stacks` is restricted to the client's own stack whenever `current_api_client.stack_id?` is true, and every controller is expected to resolve `stack` through that scoped relation [3](#0-2) . This is exactly the equality binding the analog scan looks for: `stack authorized by token == stack touched by the request`.

`Api::CCMenuController` breaks that equality. It overrides `stack` to bypass the scoped `stacks` relation entirely and instead loads any stack directly from the request parameter:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [4](#0-3) 

### Finding Description
- `require_permission :read, :stack` only checks that the token has the `read:stack` permission string; it never checks which stack the token is scoped to [5](#0-4) [6](#0-5) .
- The stack-scoping is only enforced through the `stacks` helper (`Stack.where(id: current_api_client.stack_id)` when `stack_id?` is true) used by `stack` in `BaseController` [3](#0-2) .
- `CCMenuController` redefines `stack` to call `Stack.from_param!(params[:stack_id])` directly, never consulting `stacks`/`current_api_client.stack_id` [7](#0-6) .
- As a result, a token that GitHub/Shipit administrators intentionally scoped to a single stack (e.g., `here_come_the_walrus`, scoped to `shipit`) can present any other `stack_id` in the URL and still receive a `200 OK` XML CCMenu status payload for that unrelated stack, because `require_permission :read, :stack` passes (the token has `read:stack`) and `stack` no longer checks `current_api_client.stack_id`.
- This is a "stack a token authorizes" (`current_api_client.stack_id`) vs. "stack it touches" (`params[:stack_id]` used by the overridden `stack` method) binding break, matching the reported bug class of a control that is skipped for the "not yet applicable"/differently-implemented code path (here, the `CCMenuController`'s bespoke `stack` override) while the primary path (`BaseController#stack`) enforces it correctly.
- Existing tests only exercise `Api::StacksController#index`'s "an api client scoped to a stack will only see that one stack" behavior [8](#0-7) ; the equivalent scoping assertion is never tested against `Api::CCMenuController`, and the code confirms it would fail.

### Impact Explanation
This qualifies as High under the listed impact criteria: "escalation into `Shipit.github_teams` authorization" / "unauthenticated read of stack state, task streams or deploy output" analog — specifically an authenticated-but-scope-limited token gains unauthorized read access to another stack's deploy/build status (last build status, last build label, activity, web URL) that its issuer never intended to expose, via `Api::CCMenuController#show` rendering `shipit/ccmenu/project` for an arbitrary stack [9](#0-8) .

### Likelihood Explanation
Any holder of a legitimately-issued, stack-scoped API token (e.g., a CI dashboard integration token restricted to one team's stack) can trivially exploit this by changing the `stack_id` segment of the CCMenu URL; no additional secrets or privilege escalation is required, only knowledge/guessing of another stack's slug (`owner/repo/environment`), which is often predictable or discoverable via the (also token-gated but differently-scoped) `Api::StacksController#index`.

### Recommendation
Remove the bespoke `stack` override in `Api::CCMenuController`, or reimplement it to go through the same `stacks` scoping used by `BaseController#stack` (i.e., `stacks.from_param!(params[:stack_id])`), so that a stack-scoped `ApiClient` cannot resolve any stack other than the one it is bound to.

### Proof of Concept
1. Admin creates a stack-scoped API client for stack `shopify/shipit-engine/production` with permission `read:stack` (as in fixture `here_come_the_walrus`) [1](#0-0) .
2. Attacker holding that token issues:
   `GET /api/stacks/other-org/other-repo/production/ccmenu?token=<here_come_the_walrus token>` (or via `Authorization: Basic`).
3. `authenticate_api_client` succeeds (valid token) [10](#0-9) ; `require_permission :read, :stack` passes because the token carries `read:stack` [6](#0-5) ; `stack` resolves `other-org/other-repo/production` directly via `Stack.from_param!`, ignoring that the token is scoped to a different stack [4](#0-3) .
4. Response returns `200 OK` with the unrelated stack's build/deploy status XML, confirming the scope-binding bypass.

### Citations

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
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

**File:** app/controllers/shipit/api/base_controller.rb (L48-61)
```ruby
      def authenticate_api_client
        @current_api_client = if Shipit.disable_api_authentication
                                UnlimitedApiClient.new
                              else
                                BasicAuth.authenticate(request) do |*parts|
                                  token = parts.select(&:present?).join('--')
                                  ApiClient.authenticate(token)
                                end
                              end
        return if @current_api_client

        headers['WWW-Authenticate'] = 'Basic realm="Authentication token"'
        render(status: :unauthorized, json: { message: 'Bad credentials' })
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
      end
```
