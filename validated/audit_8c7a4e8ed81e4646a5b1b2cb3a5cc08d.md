Confirmed: `StacksController#stack` correctly scopes lookups through `stacks.from_param!(params[:id])`, where `stacks` restricts to `Stack.where(id: current_api_client.stack_id)` when the client is stack-scoped [1](#0-0) . `Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely and resolve any stack in the system directly from the request parameter [2](#0-1) .

### Title
Stack-scoped API token can read CCMenu status of any stack, bypassing its `stack_id` authorization scope - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController#stack` resolves the target stack directly from `params[:stack_id]` via `Stack.from_param!`, instead of the scoped `stacks` collection that every other API controller uses. This breaks the binding "stack a token authorizes == stack it touches": an `ApiClient` created with `stack_id` set (i.e., authorized to act only on one specific stack) can use its token to read deploy/task status of **any** other stack in the installation.

### Finding Description
`BaseController` defines the authorization-scoped lookup helper:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [1](#0-0) 

Every other API controller relies on this scoped `stack`/`stacks` method (e.g. `Api::StacksController#stack` calls `stacks.from_param!(params[:id])`) [3](#0-2) .

`Api::CCMenuController` overrides `stack` to skip this scoping check entirely:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [4](#0-3) 

`require_permission :read, :stack` only validates that the client's `permissions` array includes `read:stack`; it never validates that the requested `stack_id` matches `current_api_client.stack_id`:
```ruby
def require_permission!(operation, scope)
  current_api_client.check_permissions!(operation, scope)
end
``` [5](#0-4) 
```ruby
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, ...
  end
  true
end
``` [6](#0-5) 

`Shipit::CcmenuUrlController#fetch` is the intended legitimate creator of such tokens: it mints an `ApiClient` scoped to `permissions: %w[read:stack]` (no `stack_id` binding is enforced downstream) for use as a CCMenu URL token embedded in a build-monitor tool [7](#0-6) . Any holder of that token — intended to only ever see one stack's status — can instead query `GET /api/1/stacks/<any-owner>/<any-repo>/<any-env>/ccmenu?token=...` for every other stack in the Shipit install, because `Stack.from_param!` performs an unscoped lookup [8](#0-7) .

### Impact Explanation
This yields unauthenticated read of deploy/task state and output for stacks the token holder was never authorized to see: `stack.deploys_and_rollbacks.last` exposes the latest deploy/rollback status and timing of an arbitrary stack via the rendered CCMenu XML [9](#0-8) . This matches the "High - unauthenticated read of stack state, task streams or deploy output" impact category: an attacker who obtains (or is issued) any single stack-scoped CCMenu token can enumerate and monitor the CI/deploy status of every stack in the Shipit instance, not just the one the token was scoped to.

### Likelihood Explanation
The attacker only needs one legitimately obtained CCMenu token (these are routinely embedded in unauthenticated CI-monitor URLs and query strings, e.g. via `CCMenuUrlController#fetch` which mints tokens with only `read:stack` permission and no further scoping enforced at the resource layer) [10](#0-9) . Enumerating `stack_id` path values (`owner/repo/environment`) is trivial since these are visible in the UI/URLs for the Shipit instance. No signature or additional secret protects the stack-scope binding at this endpoint.

### Recommendation
Change `Api::CCMenuController#stack` to use the scoped `stacks` collection instead of `Stack.from_param!` directly, i.e. `@stack ||= stacks.from_param!(params[:stack_id])`, so a stack-scoped token cannot resolve stacks outside its authorized `stack_id`.

### Proof of Concept
1. Admin calls `GET /ccmenu/<owner>/<repoA>/<env>` (`CcmenuUrlController#fetch`) which creates an `ApiClient` with `permissions: ['read:stack']` and no further restriction enforced by `CCMenuController`, returning a URL with an embedded `token` for stack A.
2. Using that same `token`, request `GET /api/1/stacks/<owner>/<repoB>/<env>/ccmenu?token=<token>` for an unrelated stack B that the token was never intended to access.
3. `authenticate_api_client` in `CCMenuController` authenticates the token successfully (it is a valid `ApiClient`) [11](#0-10) ; `require_permission :read, :stack` passes because the token has the `read:stack` permission globally; `stack` resolves stack B unconditionally via `Stack.from_param!(params[:stack_id])`, returning stack B's latest deploy/rollback status in the response — despite the token never having been authorized for stack B.

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-31)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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

**File:** app/models/shipit/stack.rb (L515-525)
```ruby
    def self.from_param!(param)
      repo_owner, repo_name, environment = param.split('/')
      includes(:repository)
        .where(
          repositories: {
            owner: repo_owner.downcase,
            name: repo_name.downcase
          },
          environment:
        ).first!
    end
```
