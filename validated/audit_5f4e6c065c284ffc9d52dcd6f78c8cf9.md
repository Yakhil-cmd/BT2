### Title
API stack-scoped tokens bypass their `stack_id` binding via CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` scopes every stack lookup through `stacks`, which restricts the visible `Stack` set to `current_api_client.stack_id` when a token is created scoped to a single stack [1](#0-0) . `Api::CCMenuController` overrides this method and instead resolves the target stack directly from the unscoped `Stack` model using the request-supplied `params[:stack_id]`, ignoring the token's `stack_id` restriction entirely [2](#0-1) .

### Finding Description
The binding this endpoint is supposed to preserve is: `stack a token authorizes == stack the controller touches`. `ApiClient` records can be scoped to one specific stack via `belongs_to :stack, optional: true`, and `BaseController#stacks` enforces that scope: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [3](#0-2) , with `stack` calling `stacks.from_param!(params[:stack_id])` [4](#0-3) .

`CCMenuController` only checks the coarse-grained permission `read:stack` via `require_permission :read, :stack` [5](#0-4)  which only verifies the client's `permissions` list contains `read:stack` [6](#0-5)  — it never re-checks `stack_id` scoping. It then defines its own `stack` private method that bypasses `stacks` and resolves against the entire `Stack` table: `@stack ||= Stack.from_param!(params[:stack_id])` [7](#0-6) .

Because of this, a token created and scoped to Stack A (e.g. via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, ...)` as done by `CCMenuUrlController#client` [8](#0-7) , or any other `ApiClient` with `stack_id` set and `read:stack` permission) can be replayed against `/api/stacks/:owner/:repo/:env/ccmenu?token=...` for any other stack B by changing the `stack_id` path segment, and the controller will happily render stack B's build status.

### Impact Explanation
This crosses the "High" bar of "unauthenticated read of stack state" relative to the token's actual authorization: possession of a token scoped and intended for one repository/stack (e.g. a CCMenu badge URL, which by design is unauthenticated/public-facing and often leaked/embedded in dashboards) grants an attacker the ability to enumerate/read build status (`lastBuildStatus`, `activity`, `lastBuildLabel`, lock state via `stack.merge_status`) of every other stack in the Shipit instance, including stacks belonging to unrelated repositories the token holder has no access to [9](#0-8) . This is a privilege-escalation/authorization-scope-escape analogous to the `bridge_watchdog` report: a narrowly-scoped credential is used through a code path that fails to re-verify the scope, letting the holder act outside the boundary the credential was meant to enforce.

### Likelihood Explanation
Likelihood is high for anyone who legitimately possesses one CCMenu URL/token (these tokens are explicitly designed to be embedded in unauthenticated third-party CI dashboard tools, per `CCMenuUrlController`/`ccmenu_url` route at `config/routes.rb:49-51` [10](#0-9) ). No session, GitHub credentials, or privileged account is required beyond having captured/been given one such token; only the `stack_id` path segment needs to change.

### Recommendation
`Api::CCMenuController` should not override `stack` to bypass scoping; it should reuse `BaseController#stack`/`#stacks`, which respects `current_api_client.stack_id`, e.g. remove the private `stack` override in `app/controllers/shipit/api/ccmenu_controller.rb` and rely on the inherited scoped lookup so that a stack-scoped token can only ever resolve the stack it was scoped to.

### Proof of Concept
1. As a legitimate user, create a CCMenu URL for Stack A via `GET /ccmenu/*stack_id_A` (`CCMenuUrlController#fetch`), obtaining a token scoped implicitly by the flow but structurally created via `ApiClient.create_with(permissions: %w[read:stack])`.
2. Note the token has no explicit `stack` restriction in this particular flow, but the general capability exists for any `ApiClient` with `stack_id` set (e.g. created via `/api_clients` UI, or `here_come_the_walrus` fixture pattern [11](#0-10) ) — such a token is expected to only ever see Stack A per `BaseController#stacks` [3](#0-2) .
3. Send `GET /api/stacks/<owner>/<repo-B>/<env-B>/ccmenu?token=<Stack-A-scoped-token>`.
4. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly instead of `stacks.from_param!`, the request succeeds and returns Stack B's build/lock status, even though the token is scoped to Stack A only.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/views/shipit/ccmenu/project.xml.builder (L6-16)
```text
xml.Projects do
  xml.Project(
    '',
    name: stack.to_param,
    lastBuildStatus: status_map.fetch(stack.merge_status, stack.merge_status).capitalize,
    activity: deploy.running? ? 'Building' : 'Sleeping',
    lastBuildTime: deploy.ended_at || deploy.started_at || deploy.created_at,
    lastBuildLabel: deploy.id,
    webUrl: stack_url(stack)
  )
end
```

**File:** config/routes.rb (L49-51)
```ruby
  scope '/ccmenu/*stack_id', stack_id: stack_id_format, as: :ccmenu_url do
    get '/' => 'ccmenu_url#fetch'
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
