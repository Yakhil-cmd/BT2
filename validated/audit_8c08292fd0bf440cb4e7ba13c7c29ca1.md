## Finding: Stack-scoped API token authorization bypass in CCMenu endpoint

### Title
Stack-scoped API token can read any stack's build status via `Api::CCMenuController` - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::CCMenuController#stack` re-implements stack lookup by calling `Stack.from_param!(params[:stack_id])` directly, bypassing the scope enforcement that `Api::BaseController#stacks`/`#stack` normally apply for `ApiClient` tokens that are restricted to a single stack (`stack_id`). This lets a client holding a token scoped to Stack A read build/CI-status information for any other stack, breaking the equality: `ApiClient#stack_id (the stack the token authorises)` == `stack_id param (the stack the endpoint touches)`.

### Finding Description
`ApiClient` records can optionally be scoped to a single stack via `belongs_to :stack, optional: true` [1](#0-0)  . `Api::BaseController` enforces this scoping centrally:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

Every controller that relies on this `stack` helper (e.g. `Api::TasksController`) is therefore automatically limited to the stack(s) the token authorizes, in addition to the coarse `read:stack`/`write:stack`/`deploy:stack` permission check performed by `check_permissions!` [3](#0-2) .

`Api::CCMenuController`, however, overrides `stack` and skips the `stacks` scoping entirely:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [4](#0-3) 

It only declares `require_permission :read, :stack` [5](#0-4) , which just calls `current_api_client.check_permissions!(:read, :stack)` — a check for the *permission string*, not for which specific stack the token is bound to. Because `check_permissions!` never consults `stack_id`, an `ApiClient` created with `stack_id` set to Stack A but with `read:stack` permission enabled can pass an arbitrary `stack_id` param for Stack B and successfully load Stack B via the unscoped `Stack.from_param!`.

The equality that should hold and is broken:
`current_api_client.stack_id` (the stack the token was provisioned/authorized for) == `stack.id` (the stack whose data is actually rendered by `#show`).

Before the request: token is bound to Stack A only, intended to only ever resolve Stack A.
After the request: the controller renders build state for whatever `stack_id` the client supplies, including stacks the token has no association with.

### Impact Explanation
`#show` renders `shipit/ccmenu/project` with the target stack's build status: `name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, and reflects `locked?`/`lock_reason` state (a locked stack renders as `Failure`) [6](#0-5) . A holder of a narrowly-scoped API token (e.g. an integration meant to see only its own stack's CI status) can enumerate and disclose the deploy/CI status and lock state of every stack in the Shipit instance, including stacks belonging to unrelated repositories/teams — an unauthorized cross-stack read of stack state that the token was never granted access to. This matches the "unauthenticated read of stack state" category (the token is authenticated but not authorized for the target stack, i.e. an authorization-scope bypass), which is rated High.

### Likelihood Explanation
Exploitation only requires possession of any valid `ApiClient` token that has `read:stack` permission and is scoped to a specific stack (`stack_id` set) — a common configuration for handing out a restricted, single-stack integration token, e.g. fixtures such as `here_come_the_walrus` which is scoped to the `shipit` stack [7](#0-6) . No additional privileges are needed; the attacker simply supplies a different `stack_id` in the request to `Api::CCMenuController#show`.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped lookup from `BaseController`:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so it honors `current_api_client.stack_id?` scoping like every other controller inheriting from `Api::BaseController`.

### Proof of Concept
1. Create/obtain an `ApiClient` token scoped to Stack A (`stack_id` set to Stack A's id) with `read:stack` permission (e.g. akin to the `here_come_the_walrus` fixture).
2. Using that token, issue `GET /api/stacks/<StackB-owner>/<StackB-name>/<env>/ccmenu.xml` (or the equivalent CCMenu route) with `stack_id` pointing at Stack B, a stack unrelated to the token.
3. Observe that `Api::CCMenuController#show` returns HTTP 200 with Stack B's `name`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, and lock status — despite the token only being authorized for Stack A. Compare against `Api::TasksController`, which uses the scoped `stack` helper and would correctly reject (404, because `stacks` is limited to `Stack.where(id: current_api_client.stack_id)`) the same cross-stack `stack_id`.

### Citations

**File:** app/models/shipit/api_client.rb (L1-10)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-7)
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L33-45)
```ruby
      test "xml contains required attributes" do
        get :show, params: { stack_id: @stack.to_param }
        project = get_project_from_xml(response.body)
        %w[name activity lastBuildStatus lastBuildLabel lastBuildTime webUrl].each do |attribute|
          assert_includes project, attribute, "Response missing required attribute: #{attribute}"
        end
      end

      test "locked stacks show as failed" do
        @stack.lock('test', @user)
        get :show, params: { stack_id: @stack.to_param }
        assert_payload 'lastBuildStatus', 'Failure'
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
