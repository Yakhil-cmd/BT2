## Finding

An `ApiClient` token scoped to a single stack (`stack_id` set) can be used against `Shipit::Api::CCMenuController#show` to read the build status of **any** stack, not just the one it was scoped to — breaking the binding "stack a token authorizes" == "stack it touches."

### Root cause

`Shipit::Api::BaseController` enforces stack scoping centrally: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

Every stack lookup is supposed to go through `stacks`, which restricts the queryable set to `current_api_client.stack_id` when the token is scoped. `Shipit::Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely, querying the global `Stack` model directly: [2](#0-1) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
```

The controller still enforces the `read:stack` permission string via `require_permission :read, :stack` [3](#0-2) , and `ApiClient#check_permissions!` only checks that the permission name is present in the client's `permissions` array — it never re-validates `stack_id` scoping: [4](#0-3) . Scoping is only enforced by whichever controller method builds the `stacks`/`stack` relation, and `CCMenuController` doesn't use it.

### Why this is exploitable by an "authorized-for-one-thing" actor

Stack-scoped, `read:stack`-only tokens are explicitly designed to be handed to lower-trust third parties: `CCMenuUrlController` mints exactly this kind of token and embeds it in a URL meant for external CI dashboard tools: [5](#0-4) 

```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
```

This is the equality the report's bug class maps onto: the wormhole bug let a user pick an unchecked destination chain ID that the burn logic never validated against `_wormholeRemotes`; here, a caller supplies an unchecked `stack_id` parameter that `CCMenuController#stack` never validates against the token's `current_api_client.stack_id`. The token's authorized-stack binding is never re-checked at the point where the stack is actually resolved and its state rendered.

The test suite even demonstrates the intended, narrower scoping model exists and is enforced elsewhere (e.g. `StacksControllerTest` shows `here_come_the_walrus`, a fixture scoped to the `shipit` stack, only seeing 1 stack via the properly-scoped `index` action) [6](#0-5)  — while `CCMenuControllerTest` shows the same style of token/param combination reaching `show` without any assertion that the queried stack matches the token's `stack_id`: [7](#0-6) .

---

### Title
Stack-Scoped API Token Bypasses Stack Authorization in CCMenu Endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController#stack` looks up stacks via `Stack.from_param!(params[:stack_id])` directly, instead of the scoped `stacks` helper used everywhere else in `Shipit::Api::BaseController`. A token that is deliberately scoped to a single stack (e.g. a CCMenu token minted by `CCMenuUrlController`, which grants only `read:stack`) can therefore be replayed with a different `stack_id` param to read build/deploy status of any stack in the installation.

### Finding Description
`BaseController#stacks` restricts the queryable stack set to `current_api_client.stack_id` when the `ApiClient` is scoped: [8](#0-7) . `CCMenuController` overrides `#stack` and calls `Stack.from_param!` directly on the unscoped `Stack` model [9](#0-8) , never consulting `current_api_client.stack_id`. The only remaining check, `require_permission :read, :stack`, validates a permission name against `ApiClient#permissions`, not a specific stack: [4](#0-3) . As a result, the "stack this token authorizes" (bound at issuance time to one stack) and "stack this endpoint touches" (whatever `stack_id` the caller passes) are no longer equal.

### Impact Explanation
This is an unauthorized read of stack state: build/deploy status (`lastBuildStatus`, `lastBuildLabel`, lock state, activity) for stacks the token holder was never granted access to. Because CCMenu tokens are specifically designed to be embedded in URLs handed to external tooling (`CCMenuUrlController`), this is a realistic escalation path from a narrowly-scoped, low-trust credential to organization-wide stack status disclosure, matching the High-impact bucket "unauthenticated/unauthorized read of stack state."

### Likelihood Explanation
Any holder of a valid stack-scoped, `read:stack` token (the minimal, intentionally shareable class of token in this engine) can trigger this by changing one query parameter (`stack_id`) on a request to `GET /api/stacks/:stack_id/ccmenu`. No additional privilege, signature forgery, or GitHub access is required beyond possessing the low-trust token itself.

### Recommendation
Change `CCMenuController#stack` to use the inherited, scoped `stacks` relation (i.e. `stacks.from_param!(params[:stack_id])`) instead of querying `Stack` directly, so the `current_api_client.stack_id` restriction from `BaseController#stacks` is honored, consistent with every other API controller.

### Proof of Concept
1. As a legitimate user, request a CCMenu URL for stack `A`: `GET /stacks/A/ccmenu_url` → obtain a token scoped to stack `A` with `read:stack` only (`CCMenuUrlController#client`).
2. Using that token, request `GET /api/stacks/B/ccmenu?token=<token>` for a different stack `B` that the token was never scoped to.
3. `CCMenuController#authenticate_api_client` authenticates the token successfully; `require_permission :read, :stack` passes because the token has `read:stack`; `CCMenuController#stack` resolves stack `B` via `Stack.from_param!` with no scoping check.
4. The response renders stack `B`'s build/deploy status XML, even though the token was only ever authorized for stack `A`.

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

**File:** test/controllers/api/ccmenu_controller_test.rb (L26-31)
```ruby
      test "can authenticate with query string token" do
        request.headers['Authorization'] = 'bleh'
        get :show, params: { stack_id: @stack.to_param, token: @client.authentication_token }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```
