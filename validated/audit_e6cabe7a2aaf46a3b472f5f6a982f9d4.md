### Title
`Api::CCMenuController` bypasses stack-scoped `ApiClient` authorization, allowing any client with `read:stack` to read the state of any stack - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`ApiClient` records can be scoped to a single stack via `belongs_to :stack, optional: true` [1](#0-0)  and `Api::BaseController` enforces that scoping for every resource lookup through the `stacks`/`stack` helpers, restricting queries to `current_api_client.stack_id` when the token is stack-scoped [2](#0-1) . `Api::CCMenuController`, however, overrides `stack` to resolve directly from `params[:stack_id]` without going through the client-scoped `stacks` collection [3](#0-2) , so a token that is only supposed to authorize `read:stack` for its bound stack can be used to read the CCMenu status (build/deploy status) of *any* stack in the system, simply by changing the `stack_id` in the URL.

### Finding Description
This mirrors the float-capital "wrong index used" bug class: one identifier is checked/authorized (the `ApiClient`'s own `stack_id`), but a different, attacker-controlled identifier (`params[:stack_id]`) is the one actually acted upon.

- `ApiClient#check_permissions!` only checks that the client's `permissions` array includes `read:stack`; it never checks *which* stack is being accessed [4](#0-3) .
- The binding that keeps this safe elsewhere in the API is `Api::BaseController#stacks`, which restricts the queryable stacks to the one the client is bound to, if any: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [5](#0-4) , and `stack` resolves `params[:stack_id]` only within that scoped collection [6](#0-5) .
- `Api::CCMenuController` requires the same `read:stack` permission [7](#0-6)  but defines its own `stack` method that ignores the client-scoped collection entirely and resolves any stack by id: `@stack ||= Stack.from_param!(params[:stack_id])` [8](#0-7) .

So the equality that should hold — "stack the token authorizes == stack the controller touches" — is broken for this endpoint: `current_api_client.stack_id` (authorized stack) can differ from `params[:stack_id]` (touched stack), and the controller enforces no equality between them.

### Impact Explanation
An attacker who obtains (or is legitimately issued) a stack-scoped `ApiClient` token with only `read:stack` for Stack A can pass a different `stack_id` to `GET /api/:stack_id.xml` (CCMenu endpoint) and read the deploy/build status (`lastBuildStatus`, `lastBuildLabel`, `activity`, lock status, etc.) of any other stack B in the installation, including stacks they were never granted access to. This is an unauthorized/unauthenticated-relative-to-scope read of stack state, matching the "High" impact category of "unauthenticated read of stack state, task streams or deploy output" via an authorization scope that is bypassed.

### Likelihood Explanation
Likelihood is limited by the fact that an attacker must already possess a valid, though narrowly-scoped, `ApiClient` token (e.g. one created for a single project's CCMenu integration, as done by `CCMenuUrlController#client` [9](#0-8) , or by an admin creating a stack-scoped token). Given such a token exists (a legitimate, low-privilege use case explicitly supported by the `ApiClient.stack` association), exploitation requires only changing a URL parameter — no additional secrets, signatures, or privileged access are needed.

### Recommendation
In `Api::CCMenuController`, resolve the stack the same way `Api::BaseController` does, i.e. through the client-scoped `stacks` collection (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so a stack-scoped token cannot be used to query stacks outside its authorized scope.

### Proof of Concept
1. Create (or obtain) an `ApiClient` with `permissions: ['read:stack']` and `stack: StackA`.
2. Compute its `authentication_token`.
3. Send `GET /api/<StackB-id>.xml?token=<token>` (or with Basic Auth), where `StackB` is a stack unrelated to `StackA`.
4. `Api::CCMenuController#authenticate_api_client` succeeds (valid token) [10](#0-9) ; `require_permission :read, :stack` succeeds because the client has `read:stack` [7](#0-6) ; `stack` resolves `StackB` directly from `params[:stack_id]`, bypassing the client's `stack_id` scope [8](#0-7) .
5. Response renders `StackB`'s CCMenu XML (build/deploy status), even though the token was only meant to authorize `StackA`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
