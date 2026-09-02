### Title
CCMenu API token intended for a single stack grants read access to all stacks - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
The CCMenu integration mints a per-user `ApiClient` token intended to expose build-status information for one specific stack, but neither the token nor the controller that serves it actually scopes access to that stack. Any holder of the token can substitute an arbitrary `stack_id` and read the CI status of every stack on the Shipit instance.

### Finding Description
`CCMenuUrlController#client` creates (or reuses) an `ApiClient` with `permissions: %w[read:stack]` but never sets the `stack` association: [1](#0-0) 

Because `stack_id` is left `nil` on this client, `Shipit::Api::BaseController#stacks` — the method meant to restrict a scoped client to only its authorized stack — resolves to `Stack.all` for this token: [2](#0-1) 

On top of that, `Shipit::Api::CCMenuController` doesn't even use the (already ineffective) `stacks` scoping helper. It defines its own `stack` method that resolves directly from the request parameter with no relation to `current_api_client` at all: [3](#0-2) 

`require_permission :read, :stack` only checks that the token carries the `read:stack` permission string; it never checks which stack the token is authorized for: [4](#0-3) 

The binding that should hold is: *stack the token authorizes == stack the controller serves*. Before the PR that introduced this feature there was no such token; after it, a user requesting a CCMenu URL for stack A receives a token whose real authorization is "every stack", while the UI/feature intent and the generated URL imply "stack A only." Swapping `stack_id` in the URL (or reusing the same "CCMenu Client" token that is shared across stacks per-user, since `find_or_create_by!` keys only on `creator`+`name`) lets the token read any other stack's build status.

### Impact Explanation
This grants unauthenticated (query-string-token-only, no session) read access to build/CI status (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `webUrl`) for every stack in the Shipit instance, not just the one the token was minted for. This matches the High-impact category "unauthenticated read of stack state" since the CCMenu endpoint is designed to be consumed by external CI dashboard tools without a Shipit session, and the token — meant to be embedded in third-party tooling for a single stack/repo — silently discloses state for stacks in unrelated repositories.

### Likelihood Explanation
Likelihood is high for any user who has ever generated a CCMenu URL (a standard, documented feature reachable from the stack settings page): the token they receive and embed in third-party tooling is not scoped as they'd expect, and trivial URL parameter tampering (`stack_id`) is enough to pivot to any other stack.

### Recommendation
Set `stack: stack` when creating the `ApiClient` in `CCMenuUrlController#client`, and make `Shipit::Api::CCMenuController#stack` use the scoped `stacks` helper (`stacks.from_param!(params[:stack_id])`) from `BaseController` instead of resolving `Stack.from_param!` directly, so a client's `stack_id` restriction is actually enforced.

### Proof of Concept
1. As an authenticated Shipit user, visit stack A's settings and trigger the "CCMenu URL" fetch action, obtaining a URL such as `/api/stacks/org/repoA/ccmenu.xml?token=<TOKEN>`. [5](#0-4) 
2. Replace `stack_id` in the URL with the identifier of stack B (`org/repoB`), owned by a different team/repository, keeping the same `token`.
3. Because `CCMenuController#stack` (app/controllers/shipit/api/ccmenu_controller.rb:29-31) never checks `current_api_client.stack_id`, and the token's `stack_id` was `nil` to begin with, the request succeeds with `200 OK` and returns stack B's build status/name/activity, confirmed by the existing test pattern `get :show, params: { stack_id: stack.to_param, token: @client.authentication_token }` which the controller accepts for any `stack_id` value. [6](#0-5)

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-11)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L26-31)
```ruby
      test "can authenticate with query string token" do
        request.headers['Authorization'] = 'bleh'
        get :show, params: { stack_id: @stack.to_param, token: @client.authentication_token }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```
