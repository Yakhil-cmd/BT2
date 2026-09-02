### Title
Stack-scoped API token bypasses its `stack_id` restriction in `CCMenuController#show` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the shared `stack` resolver from `Shipit::Api::BaseController` with a version that loads *any* `Stack` by param, discarding the per-`ApiClient` stack scoping that every other API endpoint enforces. A CI/CCTray token that was deliberately created scoped to a single stack (`ApiClient#stack_id`) can be replayed against `/api/hooks/:stack_id/ccmenu` (or equivalent CCMenu route) for a different `stack_id` and will successfully read that other stack's build/deploy state.

### Finding Description
`BaseController` defines the authorization-respecting resolvers: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

Every controller that relies on the inherited `stack` method (e.g. `Api::StacksController`, `Api::TasksController`, `Api::HooksController`) is implicitly restricted: if the authenticated `ApiClient` has a `stack_id` set, it can only resolve stacks within that scope — confirmed by the existing test `"an api client scoped to a stack will only see that one stack"` in `test/controllers/api/stacks_controller_test.rb:217`.

`CCMenuController`, however, redefines `stack` to bypass this scoping entirely: [2](#0-1) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```

`require_permission :read, :stack` only checks that the token's `permissions` array contains `"read:stack"` — it never re-checks `current_api_client.stack_id`: [3](#0-2) 

So the binding that should hold — *"the set of stacks a token authorises equals the set of stacks it can touch"* (`current_api_client.stack_id? → Stack.where(id: current_api_client.stack_id)`) — is broken specifically in `CCMenuController#show`, where it becomes *"any stack the caller names in `params[:stack_id]`"*. The rendered view leaks stack name, merge/lock status, and last build/deploy timing for the un-scoped stack: [4](#0-3) 

This is precisely the class of bug named in scope: *"a stack a token authorises versus a stack it touches."* The `ApiClient` fixture `here_come_the_walrus` demonstrates the intended restriction pattern (`stack: shipit`, `permissions: [read:stack]`): [5](#0-4) 

### Impact Explanation
Any holder of a stack-scoped, read-only CCMenu/API token (the lowest-privilege token type Shipit issues, meant to expose only one stack's CI status to external tooling) can use it to obtain an unauthenticated (from the target stack's point of view) read of the state — merge/lock status, last build time/label, activity — of every other stack in the installation. This matches the in-scope High-severity criterion "escalation into `Shipit.github_teams` authorization ... unauthenticated read of stack state, task streams or deploy output." No write access, no `webhook_secret`, and no elevated privileges beyond the caller's already-issued restricted token are required; the vulnerability is precisely that the restriction meant to confine the token is not honored by this one controller.

### Likelihood Explanation
High. Exploitation is a single unauthenticated (session-free) GET request with the attacker's own low-privilege token and an arbitrary `stack_id`/`params[:token]` — `authenticate_api_client` in `CCMenuController` accepts the token via query string (`params[:token]`) making it trivial to reuse: [6](#0-5) 
No race conditions, timing, or privileged setup is needed beyond possessing any stack-scoped `read:stack` token, which by design is meant to be shared with low-trust external CI dashboards.

### Recommendation
Change `CCMenuController#stack` to reuse the inherited, scope-aware `stacks` collection instead of `Stack.from_param!` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
and remove the private override so it falls back to `BaseController#stack`. Add a regression test mirroring `"an api client scoped to a stack will only see that one stack"` for the CCMenu endpoint to ensure scoped tokens cannot resolve a foreign `stack_id`.

### Proof of Concept
1. Create (or obtain) an `ApiClient` scoped to `stack_id: A` with permission `read:stack` (e.g. via `CCMenuUrlController#fetch`/the CCMenu URL feature, or any client created with a `stack` association as in the `here_come_the_walrus` fixture).
2. Compute its `authentication_token` (`ApiClient#authentication_token`).
3. Send `GET /api/hooks/:B/ccmenu?token=<token>` (or the routed CCMenu path) where `B` is a different stack's `to_param`, not the token's authorized stack `A`.
4. Observe `CCMenuController#stack` resolves stack `B` via `Stack.from_param!(params[:stack_id])`, `require_permission :read, :stack` passes because the token has `"read:stack"`, and the response XML (`app/views/shipit/ccmenu/project.xml.builder`) discloses stack `B`'s name, lock/merge status, and latest build/deploy info — despite the token being provisioned only for stack `A`.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```
