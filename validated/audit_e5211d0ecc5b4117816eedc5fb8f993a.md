Found the analog. `Shipit::Api::CCMenuController` overrides `stack` to bypass the API-client's stack scope.

### Title
API client scoped to a single stack can read CI status of any stack via the CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` establishes the trust binding that an `ApiClient` may only touch the stack it was scoped to at creation (`current_api_client.stack_id`) via the shared `stacks`/`stack` helpers [1](#0-0) . `Shipit::Api::CCMenuController`, however, overrides `stack` to look the record up globally with `Stack.from_param!(params[:stack_id])`, ignoring the client's `stack_id` scope entirely [2](#0-1) .

### Finding Description
The intended equality is: `stack a token authorises == stack it touches`. For every other API controller (`Api::TasksController`, `Api::DeploysController`, `Api::StacksController` `#show`, etc.) the `stack` method is inherited unmodified from `BaseController`, which restricts lookups to `Stack.where(id: current_api_client.stack_id)` when the client is scoped to one stack [1](#0-0) . `CCMenuController` redefines `stack` to call `Stack.from_param!(params[:stack_id])` directly against the unscoped `Stack` relation, breaking the binding: a token issued only for stack A can be used to fetch CI/build status for stack B by simply supplying stack B's id in the URL [3](#0-2) . The controller only requires `read:stack` permission via `require_permission :read, :stack`, which is a permission-string check (`ApiClient#check_permissions!`) unrelated to which stack ID is in scope [4](#0-3) , and `authenticate_api_client` is overridden here only to also accept a `params[:token]` query-string token, not to add stack scoping [5](#0-4) .

This mirrors the report's bug class: a check performed on one identifier (the permission string / signature) while a materially different identifier (the actual stack ID acted upon) is left unchecked.

### Impact Explanation
The CCMenu endpoint is designed to expose build/CI status per stack, and stack-scoped tokens are routinely handed to third-party CI dashboard tools (see `CCMenuUrlController`, which mints a `read:stack`-only, stack-scoped `ApiClient` for exactly this purpose) [6](#0-5) . Any holder of such a scoped token/URL (an unprivileged actor who was only meant to see one stack's status) can read the last build status, activity and label of any other stack in the deployment, i.e., an unauthenticated/unauthorized read of stack state, which the rules class as a High-impact escalation ("unauthenticated read of stack state, task streams or deploy output").

### Likelihood Explanation
The exploit requires nothing beyond a legitimately-issued, narrowly-scoped `ApiClient` token (e.g., a CCMenu URL a user was given for one stack) and changing the `stack_id` path segment on the request — no additional secrets, GitHub access, or session are needed. Given CCMenu URLs are meant to be embedded in third-party CI-status tools and shared, likelihood of misuse/discovery is high.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController` and rely on `BaseController#stack` (backed by `stacks`, which already enforces `current_api_client.stack_id`), or explicitly re-apply the same `stack_id?` scoping check before calling `Stack.from_param!`.

### Proof of Concept
1. As an authorized admin, create a stack-scoped API client for Stack A (e.g., via `CCMenuUrlController#fetch`, which creates an `ApiClient` with `permissions: %w[read:stack]` and a `stack_id` set to A) [6](#0-5) .
2. Obtain that client's `authentication_token`.
3. Issue `GET /api/ccmenu/<Stack-B-id>?token=<token>` where Stack B is a different, unrelated stack.
4. Because `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` without checking `current_api_client.stack_id`, the request succeeds with `200 OK` and returns Stack B's CI status, despite the token only being authorized (`stack_id`) for Stack A.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
