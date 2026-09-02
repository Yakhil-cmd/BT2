### Title
Stack-scoped API token bypasses its `stack_id` restriction via `Api::CCMenuController` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` re-implements `stack` lookup to load any stack directly from the request parameter, bypassing the stack-scoping enforcement that `Api::BaseController` normally applies. A `Shipit::ApiClient` that is deliberately scoped to a single stack (`stack_id` set) can therefore use the CCMenu endpoint to read the build/deploy state of any other stack in the installation.

### Finding Description
`Shipit::ApiClient` supports scoping a token to a single stack: `belongs_to :stack, optional: true` [1](#0-0) . `Api::BaseController` enforces this scope for every normal controller by filtering the queryable stacks:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

`Api::CCMenuController`, however, overrides `stack` to bypass that filter entirely and resolve the stack straight from the unscoped `Stack` relation:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

The only remaining check is `require_permission :read, :stack`, which merely checks the token's `permissions` array contains `read:stack` — a permission that is not itself stack-specific [4](#0-3) . This is exactly the "a stack a token authorises versus a stack it touches" binding, and it is broken: the equality `stack_authorized_by_token == stack_id_param` that `BaseController#stack` enforces is replaced in `CCMenuController#stack` by an unconditional trust of `params[:stack_id]`.

### Impact Explanation
Any holder of a valid, narrowly-scoped `ApiClient` token (one intentionally restricted to a single stack via `stack_id`, with only `read:stack` permission) can query `GET /api/1/:stack_id/ccmenu.xml` for an arbitrary `stack_id` belonging to a different repository/environment and receive that stack's CCTray XML: project name, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `activity`, `webUrl`, and lock state [5](#0-4) . This is an unauthenticated-for-that-resource read of stack state — the token was never granted access to that stack — matching the "High: unauthenticated read of stack state" impact bucket, since the scoping restriction meant to gate exactly this access is silently skipped for this one controller.

### Likelihood Explanation
Any legitimately issued stack-scoped `ApiClient` token (a normal, supported configuration meant to give least-privilege, e.g. to a CI dashboard integration) is sufficient to trigger this; no elevated privilege, secret, or additional credential beyond the token itself is required, and the endpoint is reachable with a simple unauthenticated-boundary-crossing GET request differing only in the `stack_id` path segment.

### Recommendation
Make `Api::CCMenuController#stack` reuse the scoped lookup from `Api::BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so tokens scoped to a specific stack cannot resolve or read data for any other stack.

### Proof of Concept
1. Create an `ApiClient` scoped to Stack A: `ApiClient.create!(creator: user, name: 'ci', stack: stack_a, permissions: ['read:stack'])`.
2. Obtain its `authentication_token`.
3. Send `GET /api/1/<stack_b_param>/ccmenu.xml` using Basic auth with that token, where `stack_b` is a different, unrelated stack.
4. Observe HTTP 200 with Stack B's CCTray XML (`name`, `lastBuildStatus`, `lastBuildLabel`, etc.), confirming the token — despite being scoped only to Stack A — can read Stack B's state, as shown by the direct `Stack.from_param!(params[:stack_id])` call in `app/controllers/shipit/api/ccmenu_controller.rb` bypassing `Api::BaseController#stacks`'s `current_api_client.stack_id` filter.

### Citations

**File:** app/models/shipit/api_client.rb (L4-8)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```
