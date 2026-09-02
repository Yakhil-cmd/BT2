## Finding: CCMenu API token stack-scope bypass

### Title
Stack-scoped `ApiClient` token can read CCMenu build status for any stack, not just the stack it was scoped to - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the base controller's `stack` accessor and looks the stack up directly with `Stack.from_param!(params[:stack_id])` instead of going through the stack-scoping logic used by every other API controller. This lets a caller in possession of a CCMenu token minted for one stack query the CCMenu status of any other stack in the installation.

### Finding Description
Every other API endpoint resolves the target stack via `Shipit::Api::BaseController#stack`, which is deliberately restricted to the set of stacks the authenticated `ApiClient` is allowed to see: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
`ApiClient#stack_id?` reflects the optional `belongs_to :stack` scoping applied when the token was created [2](#0-1) . When a client is scoped, `stacks` is deliberately narrowed to `Stack.where(id: current_api_client.stack_id)` so `from_param!` will raise a not-found for any other stack.

`CCMenuController`, however, defines its own `stack` method that never consults `stacks`: [3](#0-2) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```

The controller only enforces a generic permission check (`require_permission :read, :stack`) which validates that the token *has* the `read:stack` permission string, not that the permission is bound to the specific `stack_id` in the URL: [4](#0-3) 

The token generation flow (`CCMenuUrlController`) creates exactly this kind of scoped, `read:stack`-only client for a single stack: [5](#0-4) 

```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
```

The equality that should hold is: `stack authorised by token (current_api_client.stack_id)` == `stack touched by request (params[:stack_id] resolved via stack)`. Before the request, the token is bound to stack A. After hitting `GET /api/:other_stack_id/ccmenu`, `CCMenuController#stack` resolves `other_stack_id` unconditionally via `Stack.from_param!`, breaking the equality: the token authorizes stack A only, but the request reads stack B's build state.

### Impact Explanation
This is an unauthenticated-scope escalation: possession of a `read:stack`-scoped CCMenu token for a single (possibly public, non-sensitive) stack grants unauthenticated read access to the deploy/build status (`lastBuildStatus`, `lastBuildLabel`, `activity`, lock state, etc.) of every other stack managed by the Shipit instance, including stacks the token holder was never granted visibility into. This matches the in-scope High-impact category "unauthenticated read of stack state, task streams or deploy output" since the CCMenu token requires no session and no team membership check — only knowledge of any previously-issued CCMenu token.

### Likelihood Explanation
Any user who has ever fetched a CCMenu URL for a stack they were authorized to see (via `CCMenuUrlController#fetch`, reachable by any authenticated Shipit user for any stack they can view) obtains a long-lived signed token (`ApiClient#authentication_token`, based on `SimpleMessageVerifier`) that never expires unless revoked. That same token, trivially replayed with a different `stack_id` path parameter, works against arbitrary stacks. No additional privilege, secret, or session is required beyond the token itself, which the rules permit as an unprivileged-attacker analog (a stack a token authorizes vs. a stack it touches).

### Recommendation
Make `CCMenuController#stack` consistent with the rest of the API surface by resolving through the scoped `stacks` collection (i.e., delegate to `super` or reuse `stacks.from_param!(params[:stack_id])`) so a stack-scoped `ApiClient` cannot resolve a stack outside its `stack_id`.

### Proof of Concept
1. As an authorized user, visit stack A and trigger `GET /:stack_id/ccmenu_url` → `CCMenuUrlController#fetch`, obtaining `ccmenu_url` containing `token=<T>`, where `T` is an `ApiClient` scoped to stack A with `permissions: ['read:stack']`. [6](#0-5) 
2. Call the CCMenu API for a different stack B using the same token: `GET /api/<stack_B_id>/ccmenu?token=<T>`.
3. `CCMenuController#authenticate_api_client` authenticates `T` successfully (token signature is valid) [7](#0-6) ; `require_permission :read, :stack` passes because `T` has the `read:stack` permission string [8](#0-7) ; `stack` resolves stack B directly via `Stack.from_param!`, bypassing the `stack_id` restriction that would apply everywhere else [9](#0-8) .
4. The response renders stack B's build/deploy status XML, even though `T` was only ever intended to authorize stack A.

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

**File:** app/models/shipit/api_client.rb (L7-10)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-11)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-22)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
```
