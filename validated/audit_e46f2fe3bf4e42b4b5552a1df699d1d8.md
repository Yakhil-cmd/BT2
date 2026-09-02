### Title
CCMenu token authorises a single stack but the controller allows it to read any stack's deploy status - ([File: app/controllers/shipit/ccmenu_url_controller.rb], [File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The CCMenu integration mints an `ApiClient` token intended to let an external CI dashboard tool poll the status of one specific stack. That token is never bound to the stack it was generated for, and the API endpoint that consumes it ignores the client's stack scoping entirely, so the token silently authorises reading the deploy status of every stack in the Shipit instance.

### Finding Description
`CCMenuUrlController#client` mints (or reuses) an `ApiClient` with permission `read:stack`, keyed only by `creator` and a fixed `name: 'CCMenu Client'`: [1](#0-0) 

Note that `stack:` is never passed to `create_with`/`find_or_create_by!`, so `ApiClient#stack_id` remains `nil` for this token — the same single token object is reused for every stack a given user requests a CCMenu URL for, since lookup is only by `creator` + fixed `name`.

The corresponding API controller then authenticates purely with this token and fetches whatever stack the caller specifies in the URL, independent of the client: [2](#0-1) 

Authorization is checked only at the operation level (`require_permission :read, :stack` → `permissions.include?('read:stack')`) via `ApiClient#check_permissions!`, with no comparison against `params[:stack_id]`: [3](#0-2) 

Contrast this with the standard `Api::BaseController` scoping mechanism, which every other API controller relies on to restrict a stack-scoped client to its own stack: [4](#0-3) 

`CCMenuController` overrides `stack` to bypass this scoping (`Stack.from_param!(params[:stack_id])` instead of `stacks.from_param!(params[:stack_id])`). The binding that should hold is: `stack the token authorises == stack the token touches`. Because the token has no `stack_id` at all and the controller doesn't check one, this reduces to `stack the token touches == any stack`, breaking the intended per-stack scope implied by the CCMenu URL UI flow.

### Impact Explanation
Anyone who obtains a single CCMenu URL/token (these are designed to be embedded in third-party CI dashboard/tray tools, are passed as a URL query parameter, and are commonly logged by proxies, browser history, or the CCMenu client itself) gains read access to the deploy/rollback status (`deploys_and_rollbacks`) of every stack in the Shipit deployment, not just the one the URL was generated for. This is an unauthenticated read of stack state, matching the High-severity criterion "unauthenticated read of stack state, task streams or deploy output."

### Likelihood Explanation
High. No privileged access is required beyond obtaining any one valid CCMenu token, which by design is meant to be shared with low-trust external tooling (desktop CI trays, monitoring dashboards) and travels in a URL. The flaw is triggered by simply changing the `stack_id` in the query path of an otherwise-valid CCMenu URL.

### Recommendation
- Bind the `ApiClient` created in `CCMenuUrlController#client` to the specific `stack` (set `stack:` on `create_with`/`find_or_create_by!`, or generate a distinct client/token per stack), and
- In `Api::CCMenuController`, resolve `stack` via the scoped `stacks` helper (as other API controllers do) instead of `Stack.from_param!`, so a stack-scoped token can only ever touch its own stack.

### Proof of Concept
1. User A visits stack `foo`'s settings and fetches its CCMenu URL: `GET /ccmenu_url?stack_id=foo` → returns `.../api/stacks/foo/ccmenu.xml?token=T`.
2. User A visits stack `bar`'s settings and fetches its CCMenu URL: `GET /ccmenu_url?stack_id=bar` → because `client` is looked up by `creator`+fixed `name` only, the same `ApiClient`/token `T` is returned (`find_or_create_by!(creator:, name: 'CCMenu Client')`).
3. Anyone holding token `T` (e.g., extracted from the `foo` CCMenu URL configured in a third-party dashboard) can call `GET /api/stacks/bar/ccmenu.xml?token=T` (or any other stack slug) and successfully retrieve stack `bar`'s deploy status, even though `T` was only ever intended to authorise `foo`.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```
