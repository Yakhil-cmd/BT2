Confirmed: `Api::StacksController#stack` correctly scopes via `stacks.from_param!` (which filters through `current_api_client.stack_id`), but `Api::CCMenuController#stack` (app/controllers/shipit/api/ccmenu_controller.rb:29-31) calls `Stack.from_param!(params[:stack_id])` directly, bypassing the per-client stack scope entirely.### Title
Api::CCMenuController bypasses per-client stack scoping, letting a stack-scoped token read any other stack's build status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
Every other stack-facing API controller resolves the target `Stack` through `BaseController#stacks`, which restricts the visible set to `current_api_client.stack_id` when the authenticated `ApiClient` is stack-scoped. `Api::CCMenuController` overrides `#stack` and resolves it via `Stack.from_param!(params[:stack_id])` directly, never going through the scoped `stacks` relation. This breaks the binding "the stack(s) a token authorizes" == "the stack the request actually touches," letting a token scoped to one stack read CCMenu build-status data (name, last build status/label/time, activity) for any other stack in the installation.

### Finding Description
`Shipit::ApiClient` supports scoping a token to a single stack via `belongs_to :stack, optional: true` [1](#0-0) . `Api::BaseController` enforces that scope centrally:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

Controllers like `Api::StacksController` rely on this by calling `stacks.from_param!(params[:id])` [3](#0-2) , so a client scoped to stack A raising `params[:id]` for stack B gets a 404 (record not found in the restricted relation).

`Api::CCMenuController`, however, overrides `#stack` to bypass this scoping entirely:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [4](#0-3) 

The controller's authorization check, `require_permission :read, :stack` [5](#0-4) , only verifies that `"read:stack"` is present in `ApiClient#permissions` — a flat capability list, unrelated to which specific stack the token is bound to [6](#0-5) . Nothing in `require_permission`/`check_permissions!` re-validates `params[:stack_id]` against `current_api_client.stack_id`.

As a result, an `ApiClient` created with a `stack_id` restriction (e.g. the `here_come_the_walrus` fixture, scoped to stack `shipit` with only `read:stack` [7](#0-6) ) can call `GET /api/stacks/<other_owner>/<other_repo>/<other_env>/ccmenu` and successfully load `#show`, because `#stack` never consults `current_api_client.stack_id`.

The equality that should hold is:
`current_api_client.stack_id (the stack the token authorizes)` == `stack.id (the stack acted upon in the ccmenu#show request)`

`Api::CCMenuController` breaks this equality by resolving `stack` from the raw `Stack` table instead of the client-scoped `stacks` relation.

### Impact Explanation
The disclosed data (`name`, `lastBuildStatus`, `activity`, `lastBuildTime`, `lastBuildLabel`, `webUrl`) via `app/views/shipit/ccmenu/project.xml.builder` [8](#0-7)  reveals whether a stack is locked/failing/building and its most recent deploy id/time/URL for any stack in the Shipit instance — including stacks the token holder was never granted access to. This is an unauthorized/authenticated read of stack state across stack boundaries (the "stack a token authorizes vs. stack it touches" trust binding), matching the High-severity class of "unauthenticated/unauthorized read of stack state."

### Likelihood Explanation
Any holder of a legitimately-issued, narrowly-scoped API token (e.g. the auto-provisioned CCMenu token from `CCMenuUrlController`, or any `ApiClient` an administrator deliberately restricted to one stack via `stack_id`) can exploit this with a single unauthenticated-beyond-token HTTP GET, simply substituting a different `stack_id` in the URL. No special privileges beyond possessing any valid `read:stack`-permitted token are required, and the request format is trivial and discoverable from `config/routes.rb` (`get '/ccmenu' => 'ccmenu#show'` under `scope '/stacks/*stack_id'`) [9](#0-8) .

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` relation, consistent with every other controller inheriting from `Api::BaseController`:

```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

removing the override so it reuses `BaseController#stack`/`#stacks`, ensuring stack-scoped tokens cannot read data for stacks outside their `stack_id`.

### Proof of Concept
1. Have an admin create (or use the existing `here_come_the_walrus`-style) `ApiClient` scoped to `stack: shipit_stack_A` with `permissions: ['read:stack']`.
2. Using that client's `authentication_token`, issue: `GET /api/stacks/other-owner/other-repo/production/ccmenu` with `Authorization: Basic base64(token)`.
3. Observe the request succeeds with `200 OK` and returns the CCMenu XML for `other-owner/other-repo/production`, even though the token is scoped only to `shipit_stack_A` — confirming `Api::CCMenuController#stack` (app/controllers/shipit/api/ccmenu_controller.rb:29-31) bypasses the per-client `stacks` scoping enforced by `Api::BaseController#stacks`/`#stack` (app/controllers/shipit/api/base_controller.rb:74-80) that other controllers such as `Api::StacksController#stack` (app/controllers/shipit/api/stacks_controller.rb:87-89) correctly rely on.

### Citations

**File:** app/models/shipit/api_client.rb (L4-21)
```ruby
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** app/views/shipit/ccmenu/project.xml.builder (L1-16)
```text
# frozen_string_literal: true

# Derived from http://timnew.me/blog/2013/04/07/multiple-project-summary-reporting-standard-cctray-xml-feed/
status_map = { 'backlogged' => 'failure', 'locked' => 'failure' }
xml.instruct!
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

**File:** config/routes.rb (L27-29)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
      resource :lock, only: %i[create update destroy]
```
