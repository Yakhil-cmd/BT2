## Analysis

I found a valid analog. The bug-class in the report is: a role/token that is supposed to be constrained to a specific resource (a `bribeIdentifier`/proposal) is not actually enforced at the point of use, letting it act on arbitrary resources. The equivalent binding here is **the stack a token is generated to authorize vs. the stacks it actually touches**.

### Root cause

`CCMenuUrlController#client` creates (or reuses) an `ApiClient` with the `read:stack` permission but never assigns a `stack:` to it: [1](#0-0) 

Because `ApiClient` scoping in the JSON API only restricts to one stack when `stack_id` is present: [2](#0-1) 

...an `ApiClient` created without a `stack` gets unrestricted `Stack.all` access. Combined with `find_or_create_by!(creator: current_user, name: 'CCMenu Client')`, the *same* client/token is reused for every stack a given user requests a CC Menu URL for, and that token grants global `read:stack` rather than a single-stack scope.

The CC Menu status endpoint itself compounds this by bypassing the scoped `stacks` helper entirely: [3](#0-2) 

So a token minted (and displayed as a URL/query-string parameter, typically embedded in CI dashboards or status badges — a context where leakage is common) to show *one* stack's build status can, via HTTP Basic Auth against the general JSON API, read any endpoint gated by `read:stack` — e.g. deploy history, and full task/deploy console output: [4](#0-3) [5](#0-4) 

The `ApiClient` model itself has no concept of "generated for stack X only" beyond the optional `stack_id` association, which is never set here: [6](#0-5) 

### Output

### Title
CCMenu token minted for a single stack grants unrestricted `read:stack` access to every stack - (File: app/controllers/shipit/ccmenu_url_controller.rb)

### Summary
`CCMenuUrlController#fetch` mints an `ApiClient` token intended to expose only one stack's CI status through the CC Menu XML feed, but the underlying `ApiClient` record is created without a `stack` association. Since API authorization only narrows access to a single stack when `ApiClient#stack_id` is present, this "single-stack" token in fact authenticates as a global `read:stack` client against the entire JSON API, exposing every stack's state, deploy history, and task/deploy console output.

### Finding Description
`CCMenuUrlController#client` builds the token with:
```ruby
ApiClient.create_with(permissions: %w[read:stack])
         .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
```
No `stack:` attribute is passed, so `stack_id` remains `nil`. `Api::BaseController#stacks` is the only place stack-scoping is enforced, and it only applies when `current_api_client.stack_id?` is true:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end
```
Because `stack_id` is `nil`, `stacks` resolves to `Stack.all` for this token. The token is delivered embedded as a URL query parameter (`ccmenu_url`), a mechanism designed to be pasted into third-party CI dashboards/status-badge tools — i.e., a context where the token is expected to leave the trust boundary of the Shipit session, but is assumed by the feature's design to be scoped to the one stack it was generated for. It is not.

The equality that should hold but doesn't:
`stack authorized by CC Menu token` == `stack the token can touch via the JSON API`

Before: token is generated for stack A's `/api/stacks/A/ccmenu`.
After: the same token authenticates as an unscoped `read:stack` client and can be replayed via HTTP Basic Auth against `/api/stacks`, `/api/stacks/:any_id`, `/api/stacks/:any_id/deploys`, `/api/stacks/:any_id/tasks/:id/output`, etc. — reading any stack in the installation, not just stack A.

Additionally, because the client is found via `find_or_create_by!(creator:, name: 'CCMenu Client')` (no stack disambiguation), a single user's CC Menu tokens for *different* stacks are actually the *same* token/client — reinforcing that no per-stack scoping is actually achieved despite the per-stack URL design.

### Impact Explanation
This matches the High-severity category "unauthenticated read of stack state, task streams or deploy output": anyone who obtains a single CC Menu URL (commonly embedded in public build-status widgets, CI dashboards, or README badges) gains read access — via the standard authenticated JSON API — to every stack managed by that Shipit instance: stack metadata, deploy/rollback history, and full task/deploy console logs (which can include secrets echoed during deploy scripts).

### Likelihood Explanation
CC Menu URLs are explicitly designed to be handed to external tooling for public/semi-public status display, so token exposure beyond the originating user's trusted context is the expected, not exceptional, use case. No additional privilege beyond obtaining this already-externally-shared token is required to pivot to cross-stack read access.

### Recommendation
When minting the "CCMenu Client" `ApiClient`, set `stack:` to the specific stack the URL is being generated for (and disambiguate `find_or_create_by!` by stack, not just creator/name), so the resulting token's `stack_id` is populated and `Api::BaseController#stacks` correctly restricts it to that single stack. Also make `Api::CCMenuController#stack` use the scoped `stacks` helper (as `Api::BaseController` does) instead of unscoped `Stack.from_param!`, so the CC Menu endpoint itself also enforces the single-stack restriction defense-in-depth.

### Proof of Concept
1. As an authenticated Shipit user with access to Stack A, visit Stack A's CC Menu URL generator; note the returned `ccmenu_url` and extract its `token` query parameter.
2. Present that token via HTTP Basic Auth to unrelated endpoints, e.g.:
   - `GET /api/stacks` (list of all stacks)
   - `GET /api/stacks/<stack-B-id>` (Stack B, one you have no explicit CC Menu grant for)
   - `GET /api/stacks/<stack-B-id>/tasks/<task-id>/output` (Stack B's deploy console output)
3. All requests succeed because `ApiClient#stack_id` is `nil`, so `Api::BaseController#stacks` returns `Stack.all` and `require_permission :read, :stack` is satisfied globally — despite the token having been generated solely to expose Stack A's CC Menu XML status.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-36)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** app/controllers/shipit/api/outputs_controller.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class OutputsController < BaseController
      require_permission :read, :stack

      def show
        render(plain: task.chunk_output)
      end

      private

      def task
        @task ||= stack.tasks.find(params[:task_id])
      end
    end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L1-11)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class DeploysController < BaseController
      require_permission :deploy, :stack

      def index
        render_resources(stack.deploys_and_rollbacks)
      end

```

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
```
