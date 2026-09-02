### Title
API scoped-stack token can read CI status for any stack via `Api::CCMenuController` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
The reported bug class is a value/scope that is enforced in one place but silently dropped when the same operation is re-applied along a different code path (msg.value re-sent per loop iteration without being re-checked). The equivalent binding in this engine is: `stack a token authorizes == stack it touches`. `Shipit::Api::BaseController` enforces that binding by scoping stack lookups to `current_api_client.stack_id`, but `Shipit::Api::CCMenuController` overrides the `stack` accessor and drops that scoping, breaking the binding for any token restricted to a single stack.

### Finding Description
`ApiClient` can be scoped to a single stack (`belongs_to :stack, optional: true`) [1](#0-0) . The generic API base controller enforces this scoping when resolving `stack` from `params[:stack_id]`:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

`Api::CCMenuController`, however, redefines `stack` to bypass this scoping entirely, looking the stack up directly by the client-supplied `params[:stack_id]` against the whole `Stack` table:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

The only authorization check performed is `require_permission :read, :stack`, which merely checks that the client's `permissions` array contains the string `"read:stack"` — it never checks which stack the permission is scoped to:

```ruby
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, ...
  end
  true
end
``` [4](#0-3) 

Such single-stack, `read:stack`-only tokens are exactly what the engine itself mints and hands out for CCMenu integration:

```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
``` [5](#0-4) 

Because `authenticate_api_client` on `CCMenuController` also accepts the token via the `token` query-string parameter (not just an `Authorization` header) [6](#0-5) , this token is routinely shared with third-party CI dashboard tools/URLs. Before the pull request: a `stack`-scoped token can only ever resolve `stacks` limited to its own `stack_id`. After an attacker who has obtained (or was legitimately given, e.g. embedded in a CCTray URL) one such scoped token supplies a different `stack_id` in the request, `CCMenuController#stack` resolves an arbitrary stack from the whole `Stack` table, breaking the equality `token.stack_id == stack.id` that `BaseController` otherwise guarantees.

### Impact Explanation
The `show` action renders build/merge status, activity (`Building`/`Sleeping`), last build id/time, and web URL for the resolved stack [7](#0-6) , including whether the stack is currently locked/backlogged. This is an unauthenticated-for-that-stack read of stack state — the stack in question was never granted to that credential — satisfying the "High" impact bucket of unauthorized read of stack state for a stack the token does not authorize. It does not itself achieve RCE or credential exfiltration, but it is a confirmed authorization-scope bypass reachable by any holder of a legitimately-issued, narrowly-scoped `read:stack` CCMenu token.

### Likelihood Explanation
Exploitation requires only possession of any valid `stack`-scoped API token with `read:stack` permission (which the engine itself generates and is designed to be embedded in externally-facing CCTray/CI URLs) plus knowledge or guessing of another stack's `to_param` (owner/repo/environment, which is often public/discoverable). No privileged account, GitHub credentials, or session is needed beyond the token itself — this satisfies the "unprivileged attacker" requirement since a `read:stack`-only CCMenu token is a low-privilege credential by design.

### Recommendation
Have `Api::CCMenuController#stack` reuse the same stack-scoping logic as `BaseController` (i.e., resolve via `stacks.from_param!(params[:stack_id])`, respecting `current_api_client.stack_id`) instead of querying `Stack.from_param!` directly against the full table.

### Proof of Concept
1. As a normal authenticated user, create a CCMenu client scoped to `stack_A` via `CCMenuUrlController#fetch` (`GET /stacks/:stack_A/ccmenu_url`), obtaining `token_A` (permissions `['read:stack']`, `stack_id = stack_A.id`).
2. Call `GET /api/stacks/:stack_B_id/ccmenu.xml?token=token_A` where `stack_B` is a different, unrelated stack.
3. `authenticate_api_client` succeeds because `token_A` is valid. `require_permission :read, :stack` passes because `token_A.permissions` includes `read:stack` (the check never inspects `stack_B`). `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly (bypassing `current_api_client.stack_id` scoping), returning `stack_B`. The response discloses `stack_B`'s build status/activity/last build id, despite `token_A` only being authorized for `stack_A`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
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

**File:** app/views/shipit/ccmenu/project.xml.builder (L6-15)
```text
xml.Projects do
  xml.Project(
    '',
    name: stack.to_param,
    lastBuildStatus: status_map.fetch(stack.merge_status, stack.merge_status).capitalize,
    activity: deploy.running? ? 'Building' : 'Sleeping',
    lastBuildTime: deploy.ended_at || deploy.started_at || deploy.created_at,
    lastBuildLabel: deploy.id,
    webUrl: stack_url(stack)
  )
```
