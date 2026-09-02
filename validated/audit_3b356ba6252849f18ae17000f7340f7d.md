### Title
Cross-stack disclosure of build/deploy status via `Api::CCMenuController` bypassing stack-scoped API client authorization - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` overrides the `stack` lookup used by the shared `Api::BaseController` in a way that drops the stack-scoping enforcement applied to `ApiClient` tokens, letting any token with the generic `read:stack` permission read the CCMenu status (build/deploy state) of every stack in the installation, not just the stack the token was authorized for.

### Finding Description
`Shipit::Api::BaseController` scopes which stacks an `ApiClient` may see based on the client's own `stack_id`: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

`ApiClient` has an optional `belongs_to :stack` association, and permission checks (`check_permissions!`) only verify that the string `"read:stack"` is present in the client's `permissions` array — they never verify *which* stack the request targets: [2](#0-1) [3](#0-2) 

The actual per-stack authorization boundary is enforced entirely by `stack`/`stacks` in `BaseController`, which restrict the queryable relation to `Stack.where(id: current_api_client.stack_id)` whenever the client is bound to a specific stack.

`Api::CCMenuController`, however, defines its own `stack` method that bypasses this scoping and queries the full `Stack` table directly: [4](#0-3) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```

Because `require_permission :read, :stack` only checks `permissions.include?("read:stack")` and never checks `current_api_client.stack_id == stack.id`, an `ApiClient` record that is bound to one specific stack (`ApiClient#stack`, used e.g. for the CCMenu integration flow and supported by the schema/fixtures such as `here_come_the_walrus`) can be presented with an arbitrary `stack_id` route parameter and successfully retrieve `Api::CCMenuController#show` output for **any** stack in the deployment, not only the one it is scoped to.

This is the same class of bug as the reported `BootloaderUtilities` issue: a binding that is supposed to hold — "the stack a token authorizes" == "the stack the token's request actually touches" — is broken because one code path (`CCMenuController#stack`) reimplements the lookup without reapplying the enforcement that the shared code path (`BaseController#stack`/`stacks`) performs.

### Impact Explanation
This allows an attacker holding any `ApiClient` token scoped to one stack (a token that is, by design, meant to only ever be used for that one stack, e.g. distributed via the CCMenu integration URL) to enumerate/read the build and deploy status (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, lock state, etc.) of every other stack managed by the Shipit instance, including stacks belonging to different repositories/teams that the token holder has no authorization for. This matches the "unauthenticated/unauthorized read of stack state, task streams or deploy output" High-impact category, since it escalates a narrowly-scoped, low-privilege credential into an installation-wide read of deployment status.

### Likelihood Explanation
Likelihood is moderate: it requires possession of any valid `ApiClient` token that is stack-scoped and carries the `read:stack` permission (a routine, low-privilege credential intentionally distributed for narrow purposes such as CI status badges). No other special access, session, or elevated privilege is required beyond having such a token; the attacker only has to swap the `stack_id` in the request path to a stack they are not authorized for.

### Recommendation
Make `Api::CCMenuController#stack` reuse the shared scoping logic instead of querying `Stack` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so it inherits the `current_api_client.stack_id` restriction from `BaseController#stacks`. More generally, audit all controllers that override `stack`/`stacks` lookups (or otherwise query `Stack`/`Task`/`Deploy` directly using request params) to ensure they always route through the client-scoping helper rather than re-implementing lookups that silently drop the authorization check.

### Proof of Concept
1. Create (e.g., via Rails console/seed data, mirroring the `here_come_the_walrus` fixture pattern) an `ApiClient` with `permissions: ["read:stack"]` and `stack: <StackA>`.
2. Using this client's `authentication_token` for Basic Auth, request:
   `GET /api/stacks/<StackA-owner>/<StackA-name>/<StackA-env>/ccmenu`
   → succeeds as expected (authorized stack).
3. Using the same token, request a different stack's CCMenu endpoint:
   `GET /api/stacks/<StackB-owner>/<StackB-name>/<StackB-env>/ccmenu`
   → `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly (bypassing `BaseController#stacks`'s `current_api_client.stack_id` filter), so the request returns `200 OK` with `StackB`'s CCMenu status XML (`lastBuildStatus`, `activity`, etc.) even though the token is only authorized for `StackA`.

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

**File:** app/models/shipit/api_client.rb (L7-21)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```
