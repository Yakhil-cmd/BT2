## Finding

An unprivileged-attacker analog of the underflow bug exists in `Shipit::Api::CCMenuController`, where the binding "a stack a token authorises versus a stack it touches" is broken.

### Title
Stack-scoped API token can read the build/deploy status of any stack via `CCMenuController` - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::ApiClient` records can be scoped to a single stack via `belongs_to :stack, optional: true` [1](#0-0) . `Shipit::Api::BaseController` enforces that scope by filtering the `stacks` relation the client is allowed to see: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`, and the base `stack` accessor resolves the requested resource *through that filtered relation* (`stacks.from_param!(params[:stack_id])`) [2](#0-1) .

`CCMenuController`, however, overrides `stack` to bypass this scoping entirely and resolve the resource directly from the unfiltered `Stack` model:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

It also overrides authentication to accept any valid `ApiClient` token, without re-checking stack ownership:
```ruby
def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
``` [4](#0-3) 

The only authorization check applied is `require_permission :read, :stack` [5](#0-4) , which only validates that the string `"read:stack"` is present in `permissions` via `ApiClient#check_permissions!` [6](#0-5)  — it never validates *which* stack the permission applies to. That check is `Stack`-id agnostic by design; the actual scoping is supposed to happen only through the `stacks`/`stack` helpers in `BaseController`, which `CCMenuController` deliberately re-implements without the scope filter.

### Finding Description
Equality that should hold: `token.authorised_stack_id == stack.id_touched_by_request`.

Before the request: an `ApiClient` created with `stack: some_stack` (e.g. the `here_come_the_walrus` fixture, scoped to the `shipit` stack) [7](#0-6)  is only supposed to see/read that one stack, per the intent of `stacks` in `BaseController`.

After the request: because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly instead of `stacks.from_param!(...)`, supplying a *different* `stack_id` in the request resolves and renders that other stack's build status (`show` renders `deploy.ended_at`, `running?`, and the stack's `name`/`activity`/`lastBuildStatus`/`lastBuildLabel`/`lastBuildTime`/`webUrl` fields) [8](#0-7) , even though the authenticated token was never authorized for that stack.

This is structurally identical to the reported bug class: a permission/authorization value (`clientConfig.basisPoints` / here, the `ApiClient#stack_id` scope) is validated in one place but the operative computation/resource-fetch (`totalAmountToSplit` / here, `Stack.from_param!`) uses a different, unchecked value, breaking the intended invariant.

### Impact Explanation
This matches the "High" impact category: escalation into unauthenticated/unauthorized read of stack state and deploy output for stacks the token's scope should exclude. A token minted for one project (stack) can enumerate and read the CI/deploy status of any other stack registered in the Shipit instance, including private/internal projects, purely by changing the `stack_id` request parameter.

### Likelihood Explanation
Any holder of a legitimately-issued, stack-scoped `ApiClient` token (e.g. a CI dashboard integration given restricted access to one project) can immediately exploit this by requesting `/api/stacks/:other_stack_id/cc.xml` with their own token — no additional privilege, session, or GitHub credential is required beyond the token they already legitimately possess for their own stack.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` relation (as `BaseController#stack` does) instead of `Stack.from_param!` directly, so the `ApiClient#stack_id` scope is enforced consistently across all `Api::BaseController` subclasses.

### Proof of Concept
1. Create/obtain an `ApiClient` token scoped to `stack_a` with `permissions: ['read:stack']` (e.g. via `CCMenuUrlController#client` if it were stack-scoped, or any admin-issued scoped token).
2. Request `GET /api/stacks/:stack_b_id/cc.xml?token=<stack_a_token>` for an unrelated `stack_b`.
3. Observe that `authenticate_api_client` succeeds (token is valid), `require_permission :read, :stack` passes (`read:stack` is in the permission list, scope-agnostic), and `stack` resolves `stack_b` directly via `Stack.from_param!`, returning `stack_b`'s deploy/build status despite the token only being authorized for `stack_a`. [9](#0-8) [10](#0-9)

### Citations

**File:** app/models/shipit/api_client.rb (L4-8)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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

**File:** app/controllers/shipit/api/base_controller.rb (L74-84)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end

      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```
