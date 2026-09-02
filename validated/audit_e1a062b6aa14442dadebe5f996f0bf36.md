### Title
Stack-scoped API tokens bypass their stack binding in the CCMenu endpoint, allowing unauthorized read of any stack's build/deploy status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
The reported bug class is: a state-mutating operation binds to the wrong scope — the flash-governance code overwrote a user's entire pending state with `flashGovernanceConfig` instead of only updating/removing the fields the just-verified action authorized, letting a value that was never actually verified for that context leak through. The equivalent binding break in this engine is between "the stack an `ApiClient` token is scoped/authorised to" and "the stack the token is actually allowed to read," in `Shipit::Api::CCMenuController`.

### Finding Description
Every other controller under `Shipit::Api::BaseController` resolves the target `Stack` through the scoped helper: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the `ApiClient` is scoped to a single stack, and `stack` looks up `params[:stack_id]` only within that restricted set. This is the binding the system relies on: `ApiClient#stack_id` (the stack the token authorizes) must equal the stack whose data is returned.

`Shipit::Api::CCMenuController`, however, overrides `stack` and bypasses this scoping entirely: [2](#0-1) 

Instead of calling the inherited `stacks.from_param!`, it calls `Stack.from_param!(params[:stack_id])` directly — an unscoped, database-wide lookup. The `require_permission :read, :stack` before_action only checks that the permissions array on the `ApiClient` record contains `read:stack`: [3](#0-2) 

`check_permissions!` never looks at `stack_id` — it only verifies the operation/scope string. So a token created (or leaked) for `stack A` with `read:stack` permission, once authenticated via `ApiClient.authenticate(params[:token])`, can call `show` with any `stack_id` param (e.g. `stack B`) and `stack` will resolve to `Stack B` regardless of the token's `stack_id` binding.

The token itself does carry this stack-scoping intent by design: `CCMenuUrlController` mints per-stack tokens with only `read:stack` permission, expected to be usable solely for the stack the URL was generated for: [4](#0-3) 

That expectation is violated by the unscoped `stack` method in `CCMenuController`.

### Impact Explanation
`show` renders `stack.deploys_and_rollbacks.last`, `stack.merge_status`, and deploy timing/build-label/URL for the target stack into the CCMenu XML feed: [5](#0-4) 

An attacker holding any valid `read:stack`-scoped CCMenu token (their own, legitimately obtained for a stack they are permitted to see) can enumerate `stack_id` params for other stacks in the same Shipit deployment and read those stacks' build/deploy state — lock status, activity, latest deploy id/time, and stack URL — without holding permission for that stack. This is an unauthenticated-relative-to-that-stack read of stack state, matching the "High" impact bucket ("unauthenticated read of stack state, task streams or deploy output").

### Likelihood Explanation
Any user who can generate one CCMenu URL for a stack they have legitimate access to (via `CCMenuUrlController#fetch`, available to any authenticated Shipit user for any stack they can view) obtains a `read:stack` token. No admin/API-client creation privilege is required beyond ordinary Shipit login. From there, exploitation is a single unauthenticated (from the target stack's perspective) GET request with a different `stack_id` — no additional credential or signature bypass is needed. This is a low-effort, deterministic bypass because the scoping check is simply never called for this controller.

### Recommendation
Change `CCMenuController#stack` to use the inherited, scoped resolver instead of a raw model lookup, e.g. `stacks.from_param!(params[:stack_id])`, so that `current_api_client.stack_id` is enforced exactly as it is in every other API controller (`DeploysController`, `CommitsController`, `StacksController`, etc.). Add a regression test asserting that a token scoped to stack A returns 404/403 when `stack_id` for stack B is supplied.

### Proof of Concept
1. As a legitimate Shipit user with access only to `stack-a`, visit the CCMenu URL feature for `stack-a`; `CCMenuUrlController#fetch` creates/returns an `ApiClient` with `permissions: ['read:stack']` and `stack_id` implicitly tied to stack-a's URL generation, yielding an authentication `token`. [6](#0-5) 
2. Send `GET /api/stacks/<stack-b-owner>/<stack-b-name>/<stack-b-env>/ccmenu.xml?token=<token>` where `stack-b` is a stack the attacker has no permission for.
3. `authenticate_api_client` succeeds via `ApiClient.authenticate(params[:token])` (the token is cryptographically valid, just scoped to a different stack). [7](#0-6) 
4. `require_permission :read, :stack` passes because `check_permissions!` only checks the permission string, not `stack_id`.
5. `stack` resolves via `Stack.from_param!(params[:stack_id])` to stack-b (unscoped), and `show` renders stack-b's real deploy/build status in the XML response — data the token was never authorized to see.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-11)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-22)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
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
