### Title
CCMenu API token is scoped to a stack in the URL but authorized against `Stack.all` — - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`CCMenuUrlController#client` mints (or reuses) a single `ApiClient` per user named `'CCMenu Client'` with the `read:stack` permission, but never sets `stack:` on it, so the client is unscoped. `Api::BaseController#stacks` only restricts visibility when `current_api_client.stack_id?` is true; for this unscoped client every `read:stack`-gated endpoint (stacks index/show, commits, release statuses, merge requests, rollback listings) returns data for the entire Shipit instance, not just the stack the user requested a CCMenu URL for. `Api::CCMenuController` additionally re-implements `stack` with `Stack.from_param!(params[:stack_id])`, bypassing the scoping helper entirely, showing the intended design assumed per-stack scoping that never actually happens.

### Finding Description
`ccmenu_url_controller.rb#fetch` builds a URL embedding `stack.to_param` for the requested stack, and appends a bearer `token` produced by: [1](#0-0) 

Because `find_or_create_by!(creator: current_user, name: 'CCMenu Client')` does not include `stack:`, `ApiClient#stack_id` stays `nil` for this record (`belongs_to :stack, optional: true`): [2](#0-1) 

`Api::BaseController#stacks`, used by every read:stack endpoint to scope visibility, only limits results when the client has a `stack_id`: [3](#0-2) 

With `stack_id` nil, `stacks` resolves to `Stack.all`. `Api::StacksController#index`, `Api::CommitsController`, `Api::ReleaseStatusesController`, `Api::RollbacksController`, etc. only check `require_permission :read, :stack` (which the CCMenu client passes) and then read from `stacks`/`stack`, exposing every stack in the installation. `Api::CCMenuController` compounds this by not even routing through `stacks`: [4](#0-3) 

So the intended binding `token.authorized_stack == requested_stack_id` (a per-stack badge/status token) is broken: the actual binding is `token.authorized_stack == Stack.all`. Because the same `'CCMenu Client'` record is reused (`find_or_create_by!` keys only on `creator` + `name`) across every stack a user requests a CCMenu URL for, one leaked CCMenu badge URL (these are designed to be embedded in external CI dashboards/status pages — the entire feature purpose is to hand this URL+token out to third-party tooling) grants read access to all stacks' commits, deploy/release statuses, hooks-adjacent metadata, and task listing endpoints reachable under `read:stack`.

### Impact Explanation
This is an unauthenticated (from the recipient's perspective — anyone holding the leaked badge URL, no Shipit session or GitHub identity needed) read of stack state across the entire Shipit instance, matching the High-severity class of "unauthenticated read of stack state, task streams or deploy output." A token that a user believes is scoped to a single, low-sensitivity CI badge in fact reads commit history, release statuses, and deploy/rollback records for every stack managed by the installation.

### Likelihood Explanation
Any authenticated Shipit user can trigger `CCMenuUrlController#fetch` for any stack they can view and obtain this over-privileged token; no special role or admin action is required, and CCMenu URLs are explicitly meant to be copy/pasted into third-party tools, increasing exposure risk.

### Recommendation
Scope the `ApiClient` created in `CCMenuUrlController#client` to the specific stack (`stack: stack`, and include the stack in the `find_or_create_by!` key so a distinct client/token is minted per stack), and make `Api::CCMenuController#stack` go through the scoped `stacks` helper (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!` directly, so the permission check enforces the same stack the URL/token was generated for.

### Proof of Concept
1. User A calls `GET /repositories/*id/.../ccmenu_url?stack_id=stackA` (or equivalent), receiving `https://shipit/.../stackA/ccmenu.xml?token=T`.
2. Inspect the underlying `ApiClient` (`name: 'CCMenu Client', creator: A`) — `stack_id` is `nil`, `permissions: ['read:stack']`.
3. Using the same token `T`, call `GET /api/stacks` (no `X-Shipit-User` needed) — `Api::BaseController#stacks` returns `Stack.all` because `current_api_client.stack_id?` is false; every stack in the instance is listed.
4. Using `T`, call `GET /api/stacks/stackB/commits` or `/release_statuses` for a stack the requester was never given access to — the request succeeds because `require_permission :read, :stack` only checks the permission string, not stack membership.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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
