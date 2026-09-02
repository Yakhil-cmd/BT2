## Title
API token stack-scope bypass in CCMenu endpoint — a stack an ApiClient is authorized for versus the stack it actually reads ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the shared `stack` accessor from `Shipit::Api::BaseController` to look the stack up directly from `params[:stack_id]` via `Stack.from_param!`, bypassing the tenant-scoping helper (`stacks.from_param!`) that every other API controller uses. As a result, an `ApiClient` that is scoped to a single stack (`stack_id` set) — and therefore only authorized to read that one stack — can be used to read build-status data for **any** stack in the installation, breaking the binding between "the stack this token is authorized for" and "the stack whose data is actually returned."

### Finding Description
Every other controller in `app/controllers/shipit/api/` (e.g. `LocksController`, `TasksController`, `StacksController`) resolves the target stack through the private `stack` method defined in `BaseController`: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id`'s stack when the client is scoped, and `Stack.all` only when it's not. This is the mechanism that turns `require_permission :read, :stack` into an actually-scoped check.

`CCMenuController`, however, defines its own `stack` method that ignores this scoping entirely and resolves any `params[:stack_id]` against the full `Stack` table: [2](#0-1) 

The controller still declares `require_permission :read, :stack`, which merely calls `current_api_client.check_permissions!('read', 'stack')` — a check against the permission *list*, not against `stack_id`: [3](#0-2) 

So the equality that should hold — `token.authorized_stack == stack.rendered` — is broken: the token's `read:stack` permission is verified, and the `stack_id` scope (meant to restrict *which* stack that permission applies to) is silently dropped for this one endpoint. Any valid token with `read:stack` (even one deliberately scoped to a single low-sensitivity stack) can enumerate `params[:stack_id]` for arbitrary `owner/repo/environment` combinations and receive that other stack's CCTray XML feed (merge/build status, last deploy id/time, web URL): [4](#0-3) 

### Impact Explanation
This is an unauthenticated-relative-to-token read of stack state (deploy/build status) belonging to stacks the caller was never granted access to. Per the rules, "unauthenticated read of stack state, task streams or deploy output" is explicitly listed as a High-severity impact category. While the CCMenu payload itself is limited (status, last build id/time, URL), it does cross the intended tenant boundary set up by `ApiClient#stack_id`, exposing the existence, deploy cadence, and current status of stacks that a scoped token should not be able to see. In multi-tenant Shipit installations where different teams/stacks are issued differently-scoped tokens, this allows privilege escalation from "read one stack" to "read all stacks' CCMenu status."

### Likelihood Explanation
Exploitation requires only possessing any valid `ApiClient` token with `read:stack` permission (which the rules note is a normal precondition, not an escalation in itself, since holding *some* API token is the baseline threat model for this class of finding) and knowing/guessing another stack's `owner/repo/environment` param. No signature forgery, no elevated permission, and no cross-controller trickery is needed — a single GET request with a different `stack_id` suffices. This is a straightforward, deterministic code-path bug (a copy/paste divergence from the shared `stack` helper), not a race condition or timing issue.

### Recommendation
Change `CCMenuController#stack` to use the same tenant-scoped resolution as the rest of the API surface:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
reusing (or delegating to) `BaseController#stacks`, so that clients scoped via `ApiClient#stack_id` cannot resolve stacks outside their assigned scope. Add a regression test asserting that a token scoped to stack A receives a 404 (not the XML feed) when requesting stack B's CCMenu URL.

### Proof of Concept
1. Create two stacks, `A` (`owner/repoA/production`) and `B` (`owner/repoB/production`).
2. Create an `ApiClient` with `permissions: ['read:stack']` and `stack_id: A.id` (i.e., scoped only to stack A) — see the scoping model in `app/models/shipit/api_client.rb`.
3. Obtain its `authentication_token` and call the ccmenu endpoint with stack B's param instead of A's:
   ```
   GET /ccmenu/owner/repoB/production?token=<A's token>
   ```
4. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly (unscoped), the request succeeds and returns stack B's `project.xml.builder` output (build status, last deploy id/time, web URL) — despite the token being provisioned only for stack A.
5. Contrast with any other API endpoint, e.g. `GET /api/owner/repoB/production` using the same token, which correctly 404s because it goes through `BaseController#stacks`/`#stack`.

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

**File:** app/views/shipit/ccmenu/project.xml.builder (L6-16)
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
end
```
