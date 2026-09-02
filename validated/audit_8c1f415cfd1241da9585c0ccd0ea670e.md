### Title
Stack-scoped API token authorization bypass in CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
The `Shipit::Api::BaseController` restricts stack-scoped `ApiClient` tokens to only their assigned stack by resolving the `stack` through a scoped relation, but `Shipit::Api::CCMenuController` overrides this method with an unscoped lookup, breaking the binding between "the stack a token authorizes" and "the stack it touches."

### Finding Description
`Shipit::ApiClient` supports an optional `stack` association, allowing an API token to be scoped to a single stack [1](#0-0) . The base API controller enforces this scope for every endpoint by deriving the visible stack set from `current_api_client.stack_id?`: [2](#0-1) 

This is a deliberate authorization invariant, confirmed by the test `"an api client scoped to a stack will only see that one stack"` [3](#0-2) .

However, `Shipit::Api::CCMenuController` (which only requires `read:stack` permission) overrides `stack` to bypass this scoping entirely, resolving the stack directly from the URL parameter with no relation to `current_api_client`: [4](#0-3) 

`authenticate_api_client` is also overridden to accept the token via a `params[:token]` query string instead of Basic Auth, but this only changes the transport of the token, not its associated permissions or `stack_id`: [5](#0-4) 

The binding broken: `token.stack_id == requested_stack_id` (enforced everywhere else via `BaseController#stacks`) is not enforced in `CCMenuController#stack`, so `token.stack_id != requested_stack_id` becomes possible while the request still succeeds.

### Impact Explanation
Any valid `ApiClient` token carrying `read:stack` permission — even one deliberately scoped to a single, less-sensitive stack — can be replayed against `/api/stacks/:stack_id/ccmenu.xml?token=...` for an arbitrary `stack_id` and will successfully render that other stack's latest deploy/rollback status (`stack.deploys_and_rollbacks.last`) via `app/views/shipit/ccmenu/project.xml.builder`. This crosses a repository/stack authorization boundary that the rest of the API strictly enforces, exposing deploy state of stacks the token was never authorized to read.

### Likelihood Explanation
The prerequisite is possession of any legitimately-issued, narrowly-scoped `ApiClient` token with `read:stack` — a routine, low-privilege credential intentionally created to be limited to one stack (e.g. via the CCMenu integration flow or an admin-issued client). No signature forgery, GitHub credentials, or session access is required; only knowledge of another stack's `to_param` (owner/name/environment), which is generally not secret. This makes exploitation straightforward once such a token exists.

### Recommendation
Have `CCMenuController#stack` reuse the scoped `stacks` relation from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of querying `Stack` directly, so stack-scoped tokens cannot be used to read data for stacks outside their `stack_id`.

### Proof of Concept
1. Admin issues an `ApiClient` scoped to `stack_id = A` with permission `read:stack` (as supported by `belongs_to :stack, optional: true` and used elsewhere in the codebase) and hands the token to a low-trust integration for stack A only.
2. That token holder requests `GET /api/stacks/B/ccmenu.xml?token=<token>` for stack B, which they are not authorized to see.
3. `authenticate_api_client` in `CCMenuController` accepts the token via `ApiClient.authenticate(params[:token])` [5](#0-4) , `require_permission :read, :stack` passes because the token does have `read:stack` [6](#0-5) , and `stack` resolves to `Stack.from_param!('B')` regardless of the token's `stack_id` [7](#0-6) .
4. The response renders stack B's latest deploy/rollback status, which the token was never scoped to access.

### Citations

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-6)
```ruby
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
