### Title
CCMenu API endpoint ignores ApiClient stack scoping, letting a stack-scoped token read any stack's deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` enforces that a stack-scoped `ApiClient` (one created with a `stack_id`) can only see the single stack it was authorized for, by routing all stack lookups through the `stacks` scoping helper: `Stack.where(id: current_api_client.stack_id)` when `current_api_client.stack_id?` is true. [1](#0-0)  `CCMenuController`, however, overrides the private `stack` method and resolves the stack directly from the request params, bypassing that scoping entirely. [2](#0-1)  This breaks the binding "the stack a token authorizes == the stack it touches": the `require_permission :read, :stack` check only validates the string permission `read:stack` against `ApiClient#permissions` [3](#0-2) , it never re-checks that the requested `stack_id` matches `current_api_client.stack_id`.

### Finding Description
`ApiClient` supports being scoped to a single stack via `belongs_to :stack, optional: true`. [4](#0-3)  The intended enforcement of that scope lives in `BaseController#stacks`/`#stack`:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [1](#0-0) 

Every other stack-scoped controller (e.g. `CommitsController`) relies on this inherited `stack`/`stacks` method and is therefore correctly scoped. [5](#0-4) 

`CCMenuController` instead defines its own `stack` that ignores `current_api_client` entirely:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [2](#0-1) 

The only authorization gate on this action is `require_permission :read, :stack`, which is satisfied by any token carrying the `read:stack` permission string — including one legitimately minted for a single, specific stack, such as the tokens auto-created by `CCMenuUrlController` (`ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')`, unscoped) or any admin-issued `ApiClient` scoped via the `stack:` fixture attribute (see `here_come_the_walrus` fixture, scoped to stack `shipit` with only `read:stack`). [6](#0-5)  `check_permissions!` never consults `stack_id`, only the `permissions` array:
```ruby
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, ...
``` [3](#0-2) 

Because `CCMenuController#authenticate_api_client` also allows the token to be supplied via a `?token=` query-string parameter (not just HTTP Basic auth) for CCTray-client compatibility, [7](#0-6)  a scoped, low-privilege token issued for one stack (e.g. shared with a CI dashboard tool for stack A) can be replayed against `GET /api/stacks/*stack_id/ccmenu?token=...` for any other `stack_id` in the deployment and still succeed, since `require_permission` passes and `stack` performs an unscoped lookup.

### Impact Explanation
This is an unauthenticated-scope read of stack state: it discloses deploy/rollback status (name, last build status/label/time, web URL) for stacks the token holder was never authorized to see, across the entire Shipit instance, via a token that was deliberately minted with a narrower scope (`ApiClient#stack_id`). Per the engine's own scoping design, this is meant to be impossible; the leak matches the "unauthenticated read of stack state" category (High impact).

### Likelihood Explanation
Likelihood is high given the trigger conditions: any legitimately-issued, single-stack-scoped, read-only `ApiClient` token (a common and intentionally low-privilege token type, e.g. the ones auto-provisioned by `CCMenuUrlController` for CI-tray integrations) is sufficient. No special permissions beyond `read:stack` and no interaction with other Shipit internals are required — just changing the `stack_id` path segment on an otherwise valid, previously-shared CCMenu URL/token.

### Recommendation
Change `CCMenuController#stack` to reuse the inherited, scope-aware lookup instead of hitting `Stack` directly:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
removing the override (or deferring to `super`), so a stack-scoped `ApiClient#stack_id` is honored exactly as it is in every other API controller.

### Proof of Concept
1. As an admin, create an `ApiClient` scoped to stack `org/repo-a/production` with only the `read:stack` permission (mirrors the `here_come_the_walrus` fixture / the client auto-created by `CCMenuUrlController#fetch`). [8](#0-7) [6](#0-5) 
2. Obtain that client's `authentication_token`.
3. Issue `GET /api/stacks/org/other-repo/staging/ccmenu?token=<token>` for an unrelated stack `org/other-repo/staging` that this client was never scoped to.
4. `authenticate_api_client` succeeds via `ApiClient.authenticate(params[:token])`; `require_permission :read, :stack` passes because the token has `read:stack`; `stack` resolves `other-repo/staging` directly via `Stack.from_param!`, bypassing the `current_api_client.stack_id` restriction that `BaseController#stacks` would otherwise enforce — the response discloses `other-repo/staging`'s deploy status/name/URL despite the token being scoped to a different stack.

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

**File:** app/controllers/shipit/api/commits_controller.rb (L1-16)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CommitsController < BaseController
      require_permission :read, :stack

      def index
        commits = stack.commits.reachable.includes(:statuses)
        commits = commits.newer_than(stack.last_deployed_commit) if params[:undeployed]

        render_resources(commits)
      end
    end
  end
end
```

**File:** test/fixtures/shipit/api_clients.yml (L12-18)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
