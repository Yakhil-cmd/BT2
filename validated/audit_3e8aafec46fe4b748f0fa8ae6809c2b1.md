### Title
Stack-scoped ApiClient token can read CCMenu status of any stack, bypassing its `stack_id` binding - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::ApiClient` supports scoping a token to a single stack via `belongs_to :stack, optional: true` [1](#0-0) . `Api::BaseController` enforces this binding by scoping the queryable stacks to `current_api_client.stack_id` before looking up `params[:stack_id]` [2](#0-1) . `Api::CCMenuController`, however, overrides `stack` to bypass that scoping entirely, breaking the equality "stack a token authorizes == stack the request touches."

### Finding Description
The `Api::BaseController#stack` helper only ever resolves stacks the current token is authorized for: [2](#0-1) 

`Api::CCMenuController` inherits `require_permission :read, :stack`, which only checks that the token carries the string permission `read:stack` — it does not check which stack the token is scoped to: [3](#0-2) 

But `Api::CCMenuController` redefines `stack` to look up `params[:stack_id]` directly against `Stack.from_param!`, completely skipping the `current_api_client.stack_id` scoping that `BaseController#stacks`/`#stack` provide: [4](#0-3) 

Stack-scoped tokens do exist in this codebase — e.g. the fixture `here_come_the_walrus` is created with `stack: shipit` and only `read:stack` permission [5](#0-4) , and `CCMenuUrlController#client` creates exactly this kind of token for a specific stack, embedding it into a per-stack CCMenu URL: [6](#0-5) 

The intended design (verified by `StacksControllerTest#"an api client scoped to a stack will only see that one stack"`) is that a stack-scoped token must never see data belonging to a different stack [7](#0-6) . `CCMenuController` violates this design: given a valid `read:stack` token scoped to stack A (`stack_id = A`), a request to `/api/1/stacks/:stack_id/cc.xml` with `stack_id: B` and that token passes `require_permission!(:read, :stack)` (the permission string check succeeds regardless of scope) and then resolves `stack` to `B` directly via `Stack.from_param!(params[:stack_id])`, ignoring the token's `stack_id`.

Before the attacker's request: token authorized_stack == A, requested_stack == A (equality holds by design).
After the attacker's request: token authorized_stack == A, requested_stack == B, yet the request still succeeds — the binding "stack a token authorizes == stack it touches" is broken.

### Impact Explanation
This allows anyone holding a `read:stack`-scoped CCMenu token issued for one stack to read the CI/deploy status (`lastBuildStatus`, `lastBuildLabel`, `activity`, lock state, etc.) of any other stack in the Shipit installation, including stacks the token holder was never granted access to. This is an unauthenticated-for-that-resource read of stack state via a legitimately scoped but narrower credential — matching the High-severity category "escalation into `Shipit.github_teams` authorization... unauthenticated read of stack state, task streams or deploy output" from the rules, since the credential's authorization boundary (one stack) is bypassed to read arbitrary stacks' state.

### Likelihood Explanation
Any party in possession of a stack-scoped CCMenu token (these are routinely generated and embedded in CCMenu URLs by `CCMenuUrlController#client`, and could leak via bookmarks, CI dashboards, or logs) can trivially exploit this by changing the `stack_id` in the URL — no additional privileges, signing keys, or session are required. The bypass is a simple method override that most reviewers would not notice since `require_permission` appears to enforce scope but does not.

### Recommendation
Remove the `stack` method override in `Api::CCMenuController` (and the equivalent one in `CCMenuUrlController`, if that's meant to be creator-scoped) and instead rely on `BaseController#stack`/`#stacks`, which properly restricts lookups to `current_api_client.stack_id` when the client is stack-scoped. If `CCMenuController` needs a custom authentication path (token via query param instead of Basic Auth), keep the `authenticate_api_client` override but ensure `stack` still goes through the inherited `stacks.from_param!(params[:stack_id])` scoping.

### Proof of Concept
1. As an authorized user, request a CCMenu URL for Stack A via `CCMenuUrlController#fetch`; this creates/reuses an `ApiClient` scoped to Stack A with `permissions: ['read:stack']` and returns a URL containing `token=<A-scoped token>`.
2. Using that same token, issue `GET /api/1/stacks/B/cc.xml?token=<A-scoped token>` where `B` is a different stack the token was never scoped to.
3. `authenticate_api_client` succeeds (token is valid), `require_permission!(:read, :stack)` succeeds (token has the `read:stack` string permission), and `stack` resolves directly to Stack B via `Stack.from_param!`, returning Stack B's build status/activity/lock information in the XML response — data the token was never authorized to see.

### Citations

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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
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
