### Title
CCMenuController bypasses ApiClient stack-scoping, letting a stack-scoped token read any stack's build status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the base `stack` lookup to load the stack directly from the request parameter instead of going through the stack-scoping used everywhere else in the API, so a token restricted to one stack can be used to fetch CI/build status for any other stack.

### Finding Description
`Shipit::Api::BaseController` establishes the binding between an authenticated `ApiClient` and the stacks it is allowed to touch: [1](#0-0) 

`stacks` restricts the visible set to `current_api_client.stack_id` when the client is scoped to a single stack, and `stack` resolves `params[:stack_id]` only within that restricted scope. Every other API controller (e.g. `Shipit::Api::StacksController`) relies on this shared, scoped `stack`/`stacks` helper, which is exactly how single-stack `ApiClient` tokens (`stack_id` column, see `belongs_to :stack, optional: true` in `ApiClient`) are supposed to be confined.

`CCMenuController`, however, defines its own `stack` method that ignores this scope entirely: [2](#0-1) 

It only enforces `require_permission :read, :stack`, which checks that the `ApiClient` has the `read:stack` permission bit — it does **not** check that the `stack_id` the token is scoped to matches the `stack_id` present in the request. `ApiClient.check_permissions!` only validates the operation/scope string, never the target stack: [3](#0-2) 

This is the direct analog of the report's root cause: a check is performed against the wrong/insufficient target (`permissions` only) while the actual object acted upon (`stack`) is fetched through a path (`Stack.from_param!(params[:stack_id])`) that was never validated against the authorization that was actually verified (`current_api_client.stack_id`). The equality that should hold — `token.stack_id == stack_being_read.id` (when `token.stack_id` is set) — is silently dropped in this one controller.

Single-stack tokens of this type are routinely created by ordinary, non-privileged users for embedding in third-party CI dashboards: [4](#0-3) 

Any authenticated Shipit user with access to a stack can mint themselves a `read:stack`-scoped CCMenu token intended to only ever see that one stack.

### Impact Explanation
An `ApiClient` token that is supposed to be restricted to a single stack (`stack_id` set, `read:stack` only) can be used to read the build/deploy status (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) of any stack in the Shipit instance simply by changing the `stack_id` route/query parameter, as confirmed by the controller test which drives requests purely off `params[:stack_id]` with no ownership assertion: [5](#0-4) 

This matches the "unauthenticated read of stack state" High-impact category: a credential meant to expose one stack's state instead exposes the state of every stack, defeating the per-stack scoping that is the entire point of `ApiClient#stack_id`.

### Likelihood Explanation
Any user who can generate a CCMenu URL for a stack they have legitimate access to (a routine, low-privilege action available to normal authenticated users) automatically holds a token that can be repointed at arbitrary `stack_id` values with a single parameter change — no cryptographic or brute-force effort required, and the bug is triggered by a single unauthenticated-to-Shipit-session GET request bearing the token.

### Recommendation
Have `CCMenuController#stack` resolve through the shared, scope-aware `stacks` helper (i.e. `stacks.from_param!(params[:stack_id])`) exactly as `BaseController` and other API controllers do, so that a stack-scoped `ApiClient` cannot resolve a `Stack` outside of `current_api_client.stack_id`.

### Proof of Concept
1. As a normal authenticated Shipit user with access to `stack-A`, visit `stack-A`'s CCMenu URL page to generate a token via `CCMenuUrlController#fetch`; this creates an `ApiClient` with `permissions: ['read:stack']` and `stack_id = stack-A.id`.
2. Call `GET /api/<stack-B-owner>/<stack-B-repo>/<stack-B-env>/ccmenu.xml?token=<token-from-step-1>` where `stack-B` is a different, unrelated stack.
3. `CCMenuController#authenticate_api_client` succeeds because the token is a valid `ApiClient` token; `require_permission :read, :stack` passes because the client has `read:stack`.
4. `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly (bypassing the `stack_id`-scoped `stacks` relation from `BaseController`), returning `stack-B` even though the token's `stack_id` is `stack-A.id`.
5. The response renders `stack-B`'s build/deploy status (name, activity, lastBuildStatus, lastBuildLabel, webUrl), which the token was never authorized to see.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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
