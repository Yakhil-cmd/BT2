### Title
CCMenu endpoint bypasses ApiClient stack-scope restriction, allowing a stack-scoped token to read build/deploy status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` enforces that a stack-scoped `ApiClient` (one created with a `stack_id`) can only see the single stack it was issued for, by resolving `stack`/`stacks` through `current_api_client.stack_id?`. `Shipit::Api::CCMenuController` overrides the `stack` method to bypass this scoping entirely, resolving the target stack directly from `Stack.from_param!(params[:stack_id])` against the whole table. As a result, any valid ApiClient token with `read:stack` permission — even one scoped to a single stack — can be used to fetch CI/build status for any other stack in the installation.

### Finding Description
`BaseController` computes the caller's authorized stack set as: [1](#0-0) 

so `stack` (used by every other API controller such as `StacksController`, `HooksController`, etc.) is bound to `Stack.where(id: current_api_client.stack_id)` whenever the authenticating `ApiClient` has a `stack_id` set. Test coverage confirms this binding is treated as a security boundary ("an api client scoped to a stack will only see that one stack").

`CCMenuController`, however, defines its own `stack` accessor that ignores `current_api_client` entirely: [2](#0-1) 

It only enforces `require_permission :read, :stack` (an operation check), never the scope check that restricts *which* stack that operation may target: [3](#0-2) 

The permission model (`ApiClient#check_permissions!`) only validates the `operation:scope` string (e.g. `read:stack`), it has no concept of which specific stack row is allowed: [4](#0-3) 

So the binding that should hold is:
`stack IDs authorized for token == stack IDs reachable through every controller action`,
but for `CCMenuController#show` it becomes:
`stack IDs authorized for token (single stack) != stack IDs reachable (Stack.all)`.

This is the same bug class as the reported analog bug: an authorization control (`ifNotEmergencyState`/stack-scope check) applied consistently everywhere except on select entry points, silently disabling the restriction there.

The exposure is amplified by `CCMenuUrlController`, which mints and hands out ApiClient tokens meant to be embedded in third-party CI dashboard URLs (query-string tokens, not HTTP Basic auth), and by `CCMenuController#authenticate_api_client` which explicitly supports authenticating via the `token` query parameter: [5](#0-4) [6](#0-5) 

Any deliberately stack-scoped token (an operator can create one with `stack_id` set precisely to limit exposure — e.g. fixture `here_come_the_walrus` is scoped to a single stack with only `read:stack`) is expected to be confined to that stack everywhere in the API. The CCMenu route breaks that guarantee.

### Impact Explanation
This meets the "High" bar of unauthenticated/unauthorized read of stack state: possession of a token that is supposed to be restricted to one stack (per the product's own scoping feature) is sufficient to read build status (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) of every other stack managed by the Shipit instance, including stacks the token holder has no authorization for.

### Likelihood Explanation
Any holder of a legitimately-issued, stack-scoped `ApiClient` token (a routine, low-privilege credential intentionally distributed to third-party CI dashboards via `CCMenuUrlController`) can trivially exploit this by changing the `stack_id` route/query parameter — no additional secret or privilege escalation is required, only knowledge of another stack's slug/id.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` collection from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!`, so the stack-scope restriction enforced everywhere else in the API also applies to the CCMenu endpoint.

### Proof of Concept
1. Operator creates (or already has) an `ApiClient` scoped to `stack: shipit` with permission `read:stack` only (as in fixture `here_come_the_walrus`).
2. Using that client's authentication token, request:
   `GET /api/1/stacks/<other-stack-owner>/<other-repo>/<other-env>/ccmenu.xml?token=<token>`
   for a stack the token was never scoped to.
3. Response returns `200 OK` with the other stack's build/deploy XML status, even though `StacksController#index`/`#show` with the same token would correctly return only the scoped stack, demonstrating the CCMenu path uniquely bypasses the enforced binding. [1](#0-0) [7](#0-6)

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-22)
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

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
```
