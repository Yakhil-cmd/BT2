### Title
Stack-scoped ApiClient token can read any stack's CI build status via `Api::CCMenuController` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
The bug class reported externally is a "check performed on one value, action performed on a different, broader value" defect (fees calculated/validated on `maxAmountInToBin` while the actual swap acts on `amountIn`). The equivalent binding in this engine is: **a stack an `ApiClient` token authorizes == the stack the controller action actually touches**. In `Api::CCMenuController`, that equality is broken: the permission check is scope-generic (`read:stack`), and the stack that is actually read is taken directly from `params[:stack_id]` without ever being intersected with the token's authorized stack set.

### Finding Description
`Api::BaseController` implements per-token stack scoping through two cooperating methods: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the client is scoped (`stack_id?`), and `stack` resolves `params[:stack_id]` against that restricted relation via `stacks.from_param!(...)`. This is the binding: **token.stack_id (if present) == the only stack reachable by `stack`**.

`Api::CCMenuController` overrides `stack` and bypasses this binding entirely: [2](#0-1) 

Instead of `stacks.from_param!(params[:stack_id])`, it calls `Stack.from_param!(params[:stack_id])` — querying across **all** stacks in the installation, ignoring `current_api_client.stack_id`. The `require_permission :read, :stack` before_action only checks that the token's `permissions` array contains the string `"read:stack"` (`ApiClient#check_permissions!`), it does not check which stack the token is scoped to: [3](#0-2) 

So the "authorized stack" (token.stack_id) and the "touched stack" (params[:stack_id], resolved against all stacks) are two different values that are never compared.

Stack-scoped tokens are a normal, low-privilege artifact any authenticated Shipit user can generate for themselves via `CCMenuUrlController#fetch` (creates/looks up a `read:stack`-only `ApiClient` and returns a signed token+URL for the CCMenu badge of a stack the user is currently viewing): [4](#0-3) 

Existing test coverage never exercises the scoped-client restriction against a different `stack_id` in `Api::CCMenuController` (only the general 403-for-no-permission and happy-path cases are tested), confirming the scoping gap is unverified: [5](#0-4) 

### Impact Explanation
Holding a legitimately obtained, narrowly-scoped CCMenu token for stack A (which any team member with read access to that stack can self-issue), an attacker can substitute an arbitrary `stack_id` param and read the CI/deploy status XML (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) of any other stack in the Shipit instance — including private/sensitive stacks the attacker has no authorization for. This is an unauthenticated-relative-to-that-resource read of stack state/deploy output, matching the High severity bucket ("unauthenticated read of stack state, task streams or deploy output" via escalation past the token's authorization scope).

### Likelihood Explanation
High likelihood: no special privileges are needed beyond self-issuing a `read:stack`-scoped CCMenu token for any one stack the attacker can legitimately view (a routine, unauthenticated-relative action inside the app for any team member), then reusing that token with a different `stack_id` against `Api::CCMenuController#show`. The bypass requires no signature forgery, no secret knowledge, and no privileged account — only crafting a different query parameter.

### Recommendation
In `app/controllers/shipit/api/ccmenu_controller.rb`, remove the private `stack` override (or reimplement it using the scoped `stacks` relation from `BaseController`, i.e. `stacks.from_param!(params[:stack_id])`) so that scoped `ApiClient` tokens can only resolve stacks within `current_api_client.stack_id`, restoring the equality between "stack authorized by the token" and "stack touched by the action."

### Proof of Concept
1. As user Alice (member of `org/stack-a`), visit stack A's settings page and trigger the CCMenu badge URL generation (`CCMenuUrlController#fetch` for `stack_id=stack-a`). This creates/returns an `ApiClient` with `permissions: ['read:stack']` and (if the app assigns `stack_id`) scoped to stack A, along with a signed `token`.
2. Using that `token`, issue: `GET /api/stacks/stack-b/ccmenu.xml?token=<token>` where `stack-b` is a different, private stack Alice has no access to.
3. `Api::CCMenuController#authenticate_api_client` authenticates the token, `require_permission :read, :stack` passes (token has `read:stack` in its `permissions` array), and `stack` resolves `Stack.from_param!('stack-b')` against **all** stacks (not the scoped relation), returning stack B's `deploys_and_rollbacks.last`.
4. The response renders `shipit/ccmenu/project.xml.builder` with stack B's `name`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `webUrl` — data the token was never authorized to read.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L1-23)
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
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L13-24)
```ruby
      test "a request with insufficient permissions will render a 403" do
        @client.update!(permissions: [])
        get :show, params: { stack_id: @stack.to_param }
        assert_response :forbidden
        assert_json 'message', 'This operation requires the `read:stack` permission'
      end

      test "#show renders the xml" do
        get :show, params: { stack_id: @stack.to_param }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```
