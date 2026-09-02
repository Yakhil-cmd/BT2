### Title
Stack-scoped ApiClient tokens can read CCMenu build status for any stack, not just their authorized stack - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` resolves the target `stack` using an unscoped `Stack.from_param!(params[:stack_id])` lookup instead of the scoped `stacks.from_param!` helper used by every other API controller. This breaks the binding between the stack an `ApiClient` token is authorized for (`ApiClient#stack_id`) and the stack the request actually touches.

### Finding Description
`Api::BaseController` defines the canonical, scope-respecting accessor: [1](#0-0) 

`current_api_client.stack_id?` restricts the visible `Stack` set to the single stack the client was scoped to at creation time. Every other API controller relies on this, e.g. `Api::StacksController`: [2](#0-1) 

However, `Api::CCMenuController` overrides `stack` to bypass this scoping entirely: [3](#0-2) 

The controller only enforces the coarse `read:stack` permission (`require_permission :read, :stack`), never checking that the requested `stack_id` matches `current_api_client.stack_id`: [4](#0-3) 

The token equality that should hold is: `token.stack_id == requested_stack.id` (when the client is stack-scoped). After the request is processed, this becomes `token.stack_id != requested_stack.id` yet the request still succeeds, because `stack` is looked up via the global `Stack` relation rather than the client-scoped `stacks` relation.

### Impact Explanation
A stack-scoped `ApiClient` token — the exact kind minted automatically by `CCMenuUrlController#client` for every logged-in user with only `read:stack` permission and normally intended to expose one project's build status — can be reused to query `/api/stacks/:stack_id/cc_menu.xml` for **any** stack on the instance, including stacks the token holder has no legitimate access to. This discloses build/deploy activity state (`lastBuildStatus`, `lastBuildLabel`, `activity`, lock state, etc.) for arbitrary stacks, which is an unauthorized read of stack state across an authorization boundary that the rest of the API enforces correctly (High impact: escalation into authorization / unauthorized read of stack state).

### Likelihood Explanation
Any holder of a stack-scoped, low-privilege `read:stack` token (which is trivially created and self-served via `GET /stacks/:id/ccmenu_url` for any authenticated Shipit user) can trigger this by simply changing the `stack_id` path parameter — no elevated privilege, secret, or additional credential is required beyond the token they already legitimately possess for their own stack.

### Recommendation
Change `Api::CCMenuController#stack` to use the scoped lookup consistent with the rest of the API:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
removing the private `stack` override entirely so it inherits `BaseController#stack`, restoring the `current_api_client.stack_id` binding.

### Proof of Concept
1. As any Shipit user, visit `GET /stacks/my-stack/ccmenu_url` to obtain a `read:stack`-only, stack-scoped `ApiClient` token/URL (see `CCMenuUrlController`) — this token is scoped to `my-stack` only. [5](#0-4) 
2. Take the returned token and issue `GET /api/stacks/OTHER-PRIVATE-STACK/cc_menu.xml?token=<token>`.
3. Because `CCMenuController#stack` uses `Stack.from_param!` instead of `stacks.from_param!`, the request succeeds and returns `OTHER-PRIVATE-STACK`'s build status/activity/lock state, even though the token is scoped only to `my-stack`. [6](#0-5)

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-12)
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

```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-36)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-18)
```ruby
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
```
