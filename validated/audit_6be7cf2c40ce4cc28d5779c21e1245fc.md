### Title
CCMenu API endpoint bypasses ApiClient stack scoping, allowing a stack-scoped token to read any stack's status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::ApiClient` can be scoped to a single stack (`belongs_to :stack, optional: true` / `stack_id`), and `Api::BaseController` is supposed to enforce that scoping for every API call that resolves a stack from `params[:stack_id]`. `Api::CCMenuController`, however, overrides the `stack` accessor to resolve the stack directly from the request params instead of going through the scoped `stacks` collection, breaking the equality "stack a token authorizes == stack the token can touch."

### Finding Description
`Api::BaseController` defines the canonical, scope-aware resolution: [1](#0-0) 

`current_api_client.stack_id?` restricts `stacks` to the single `Stack` the `ApiClient` was created for; `stack` (used by nearly every API controller) is derived from that restricted relation via `stacks.from_param!(...)`, so a token scoped to stack A can never resolve stack B.

`Api::CCMenuController` requires only the generic `read:stack` permission (not tied to a specific stack) and then defines its own `stack` method that ignores the scoped `stacks` helper entirely: [2](#0-1) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```

This resolves `Stack.from_param!` against the entire `Stack` table, not `stacks` (the client-scoped relation from the base controller). `check_permissions!` only validates the operation/scope string (`"read:stack"`), never the specific `stack_id` the client is bound to — see `ApiClient#check_permissions!`: [3](#0-2) 

So the "equality" the system is supposed to enforce — `token.stack_id == stack_being_served` — is checked in `BaseController#stack`/`#stacks` but is silently skipped by `CCMenuController#stack`. Any valid API token with `read:stack` permission (even one deliberately minted and scoped to a single, low-sensitivity stack, e.g. via `CCMenuUrlController`, which creates a `read:stack`-scoped client for a specific stack and hands the resulting `authentication_token` out in a URL) can be replayed against `/api/stacks/<other_stack>/ccmenu.xml` to read another, potentially unrelated stack's status.

`CCMenuUrlController` is exactly this kind of minting path: it creates (or reuses) a `read:stack` scoped `ApiClient` for the *current* stack and embeds its `authentication_token` in a shareable CCMenu URL: [4](#0-3) 

That token is designed to only ever reveal one stack's CI/deploy state via CCMenu (`app/views/shipit/ccmenu/project.xml.builder`), but because `Api::CCMenuController#stack` does not consult `current_api_client.stack_id`, the same token can be used to query the CCMenu XML for **any** stack in the installation, not just the one it was scoped/created for.

### Impact Explanation
This is an authorization/scoping bypass: a token that is supposed to be constrained to reading the status of one stack can instead read the deploy/build status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `activity`, `webUrl`, lock status) of every stack managed by the Shipit instance. This matches the "unauthenticated [for other stacks] read of stack state" bucket of the High-severity impact criteria — the token holder was never authenticated/authorized for those other stacks' data, yet can read it.

### Likelihood Explanation
Likelihood is moderate-to-high wherever CCMenu URLs are shared: any team member (or anyone who obtains a leaked/forwarded CCMenu URL, which is designed to be embedded in third-party CI dashboard tools) automatically holds a working, stack-scoped API token. Because `CCMenuController` never checks `current_api_client.stack_id`, that shared/leaked token trivially becomes a way to enumerate and read every other stack's build/deploy status by varying `stack_id` in the URL — no additional secret or privileged action is required beyond having one legitimately-issued CCMenu link.

### Recommendation
Make `Api::CCMenuController#stack` go through the same scoped resolution as every other API controller, i.e. reuse `Api::BaseController#stacks`/`#stack` (remove the private override, or change it to `@stack ||= stacks.from_param!(params[:stack_id])`), so that `current_api_client.stack_id?` is always honored. Additionally, consider making `ApiClient#check_permissions!` stack-aware so that any scope check for `:stack` operations also verifies the target stack id, closing this class of bug at the model layer rather than relying on every controller reimplementing scoping correctly.

### Proof of Concept
1. As a legitimate user, visit a stack overview page and let Shipit mint a CCMenu URL, which creates a `read:stack` `ApiClient` scoped to `stack_id = A` and returns a URL like `.../api/stacks/A/ccmenu.xml?token=<TOKEN>` (see `CCMenuUrlController#fetch`).
2. Obtain/share that `TOKEN` (this is the expected distribution mechanism — CCMenu URLs are meant to be pasted into external CI aggregator tools).
3. Using the same `TOKEN`, request `.../api/stacks/B/ccmenu.xml?token=<TOKEN>` for an arbitrary other stack `B` that the token was never scoped to.
4. `Api::CCMenuController#authenticate_api_client` accepts the token (it is a validly signed `ApiClient` id), `require_permission :read, :stack` passes because the token does have the generic `read:stack` permission, and `#stack` resolves `B` directly via `Stack.from_param!(params[:stack_id])` without checking `current_api_client.stack_id == B.id`. The XML response for stack `B`'s build/deploy status is returned, even though the token was only meant to reveal stack `A`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-37)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack

      class NoDeploy
        def id
          0
        end

        def ended_at
          Time.now.utc
        end

        def running?
          false
        end
      end

      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L1-24)
```ruby
# frozen_string_literal: true

require 'uri'

module Shipit
  class CCMenuUrlController < ShipitController
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
  end
end
```
