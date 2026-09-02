### Title
Cross-stack information disclosure via CCMenu API client tokens that bypass stack-scope binding - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
The reported bug class is a permanent-loss/authorization-binding failure caused by a privileged action being reachable through a path that skips a check applied everywhere else in the same system (a receiver being able to have its emissions swept only through a code path that never actually enforces the intended, narrower authorization). The closest reachable analog in shipit-engine is a broken binding between "the stack an `ApiClient` token is scoped/authorised to" and "the stack the token is actually used to read," in `Shipit::Api::CCMenuController`.

### Finding Description
`Shipit::Api::BaseController` establishes the intended binding: an `ApiClient` may be scoped to a single stack (`ApiClient#stack_id`), and every normal API action must resolve the target stack only from within that scope: [1](#0-0) 

```
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

This is the equality the system relies on for scoped tokens: `stack accessed == current_api_client.stack_id` (when the client is scoped). `Shipit::Api::StacksController#stack` follows the same pattern (`stacks.from_param!(params[:id])`), preserving the binding.

`Shipit::Api::CCMenuController`, however, overrides `stack` and never routes through the scoped `stacks` collection: [2](#0-1) 

```
private

def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
```

`authenticate_api_client` here also accepts the token from a query-string `params[:token]` (by design, to support the CCTray-style polling URL), and only verifies that the token is a *valid* `ApiClient` token with the `read:stack` permission — the `require_permission :read, :stack` check only asserts the permission bit exists (`ApiClient#check_permissions!`), it never checks the identity of the stack in `params[:stack_id]` against `current_api_client.stack_id`: [3](#0-2) 

Because `CCMenuController#stack` calls `Stack.from_param!` directly instead of `stacks.from_param!`, the equality `stack accessed == current_api_client.stack_id` is never enforced on this endpoint. Any valid, scoped `ApiClient` token (e.g. one created for a single stack via `CCMenuUrlController`, or one from `ApiClientsController`/fixtures such as `here_come_the_walrus`, which is bound to `stack: shipit`) can be replayed against `GET /api/stacks/:stack_id/ccmenu.xml` with an arbitrary `stack_id` belonging to a different, unrelated stack, and will successfully authenticate and render that other stack's status.

### Impact Explanation
This breaks the "a stack a token authorises versus a stack it touches" binding explicitly called out as in-scope. The disclosed data (`app/views/shipit/ccmenu/project.xml.builder`) includes the target stack's `merge_status`, deploy activity ("Building"/"Sleeping"), last build time/label, and lock status — i.e., unauthenticated/unauthorized cross-stack read of stack and deploy state, matching the High-severity bucket ("unauthenticated read of stack state, task streams or deploy output") because the token is scoped to a different repository/stack than the one it is used to read. [4](#0-3) 

### Likelihood Explanation
Exploitation requires possession of any single valid `ApiClient` authentication token with `read:stack` permission (these are routinely embedded in CI dashboards/CCTray URLs and are not treated as highly secret since they're designed to be pasted into third-party CCTray viewers). No further privilege, session, or GitHub credential is required — only substituting a different `stack_id` in the request path/query, which is trivial and requires no special access beyond the token itself.

### Recommendation
In `Shipit::Api::CCMenuController`, resolve `stack` through the same scoped collection used elsewhere (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so a stack-scoped `ApiClient` token can only ever resolve to the stack it was actually granted for. Apply the same standard to any other controller that overrides the base `stack`/`stacks` resolution instead of inheriting `BaseController`'s scoping.

### Proof of Concept
1. Create (or use an existing) `ApiClient` scoped to Stack A, e.g. the `here_come_the_walrus` fixture (`stack: shipit`, permission `read:stack`) — analogous to a token minted by `CCMenuUrlController#client` for a specific stack.
2. As an unrelated, unauthorized party who obtains that token (e.g. from a shared/leaked CCTray URL), issue:
   `GET /api/stacks/<STACK_B_ID>/ccmenu.xml?token=<here_come_the_walrus_token>`
   where `STACK_B_ID` is any other stack in the instance.
3. `CCMenuController#authenticate_api_client` accepts the token (it is a valid `ApiClient`), and `CCMenuController#stack` loads Stack B directly via `Stack.from_param!`, bypassing the `current_api_client.stack_id` scoping enforced everywhere else.
4. The response renders Stack B's `merge_status`, build activity, and last deploy metadata, even though the token was only ever supposed to authorize reads of Stack A — confirmed by contrast with `BaseController#stack`/`Api::StacksController#stack`, which correctly reject out-of-scope `stack_id` values via `stacks.from_param!`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-37)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
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

**File:** app/views/shipit/ccmenu/project.xml.builder (L1-16)
```text
# frozen_string_literal: true

# Derived from http://timnew.me/blog/2013/04/07/multiple-project-summary-reporting-standard-cctray-xml-feed/
status_map = { 'backlogged' => 'failure', 'locked' => 'failure' }
xml.instruct!
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
