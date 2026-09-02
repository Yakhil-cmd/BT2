### Title
Unscoped `read:stack` ApiClient token issued by the CCMenu URL feature grants unauthenticated read access to all stacks - (File: app/controllers/shipit/ccmenu_url_controller.rb)

### Summary
`CCMenuUrlController#fetch` mints a persistent `ApiClient` token intended to grant read-only CI-status access to a single stack via a shareable URL. The `ApiClient` record it creates or reuses is never scoped to that stack, so the token it hands out authorizes `read:stack` access to **every** stack in the Shipit instance, not just the one the user requested the badge/URL for. This breaks the binding "the stack a token authorizes" == "the stack the token is meant to touch."

### Finding Description
`CCMenuUrlController#fetch` builds (or reuses) an `ApiClient` like this: [1](#0-0) 

```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
```

The `find_or_create_by!` lookup keys are only `creator:` and `name:`. It never sets or filters on `stack:`, even though `ApiClient` supports an optional `stack` association meant for exactly this purpose: [2](#0-1) 

As a result, calling `fetch` for stack A returns a token for an `ApiClient` whose `stack_id` is `nil`. `Api::BaseController#stacks`, which every other API controller uses to scope a client's visibility, treats a `nil` `stack_id` as "unrestricted, see all stacks": [3](#0-2) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end
```

Because the token has `read:stack` and no `stack_id`, it authenticates against `Api::BaseController` (via HTTP Basic Auth, since `ApiClient.authenticate` only validates the signed id, independent of which controller invoked it) and can list, view, and read task/deploy output for **any** stack the Shipit instance manages — not merely the stack whose CCMenu URL the user generated.

`Api::CCMenuController` itself compounds the problem by not enforcing scope at all: it authenticates the token from the query string and resolves `stack` directly from `Stack.from_param!(params[:stack_id])`, bypassing the (still ineffective, since `stack_id` is nil anyway) scoped `stacks` helper: [4](#0-3) 

The intended trust boundary — "this URL/token exposes CI status for stack X only" — is what a user sharing a CCMenu badge URL (a common, low-sensitivity, often externally-embedded artifact, e.g. in a CI dashboard or README) would reasonably assume. In reality the token is a general-purpose `read:stack` API credential for the whole Shipit deployment.

### Impact Explanation
Any holder of a single stack's CCMenu URL (query string contains the raw `token`) can use that same token via HTTP Basic Auth against the full JSON API (`Api::StacksController`, `Api::TasksController`, `Api::DeploysController`, `Api::CommitsController`, `Api::MergeRequestsController`, `Api::OutputsController`, etc.) to read state, task streams, and deploy output for every stack in the instance — including stacks the requesting user was never authorized to see. This matches the "unauthenticated read of stack state, task streams or deploy output" High-impact criterion: CCMenu URLs are handed out to an authenticated Shipit user, but the resulting bearer token is not bound to the repository/stack the user requested, so anyone who obtains that URL/token (e.g. from a leaked CI dashboard config, browser history, proxy log, or forwarded link) gains cross-stack read access without ever authenticating to Shipit itself.

### Likelihood Explanation
Likelihood is moderate-to-high: CCMenu URLs are designed to be shared with external CI status tools (that is their entire purpose), so the token is expected to leave the trusted browser session and land in less-controlled locations (build dashboards, status widgets, logs). Because the `ApiClient` is memoized per-user (`find_or_create_by!(creator:, name:)`), the very first stack for which a given user fetches a CCMenu URL determines the token, and it is transparently reused for every subsequent stack that same user requests a badge for — increasing the chance the same broad token circulates across multiple integrations while the user believes each URL is stack-specific.

### Recommendation
Scope the `ApiClient` created by `CCMenuUrlController#client` to the requested stack, both in the lookup and creation:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, stack:, name: 'CCMenu Client')
end
```
Additionally, `Api::CCMenuController#stack` should resolve through the scoped `stacks` helper (inherited from `BaseController`) rather than `Stack.from_param!` directly, so that even a legacy unscoped token cannot be used to pull another stack's CCMenu status.

### Proof of Concept
1. As an authenticated Shipit user with access to Stack A, visit Stack A's page and trigger the "CCMenu URL" feature (`GET /stacks/.../ccmenu_url` → `CCMenuUrlController#fetch`). Note the returned `ccmenu_url`, which contains `?token=<TOKEN>`.
2. Inspect `ApiClient.find_by(creator: current_user, name: 'CCMenu Client')` — observe `stack_id` is `nil` and `permissions` is `["read:stack"]`.
3. Using `<TOKEN>` as the HTTP Basic Auth username (per `ApiHelper`/`BasicAuth.authenticate` convention used by the API), issue:
   ```
   curl -u <TOKEN>: https://<shipit-host>/api/stacks
   ```
   This returns the full list of stacks in the instance, including Stack B (which the token holder was never granted access to).
4. Continue to fetch `/api/stacks/<stack_b_id>/tasks`, `/api/stacks/<stack_b_id>/deploys/<id>` (via `Api::OutputsController`/`Api::DeploysController`) to confirm task/deploy output for Stack B is readable with the Stack-A-issued CCMenu token.

### Citations

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

**File:** app/models/shipit/api_client.rb (L1-21)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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

**File:** app/controllers/shipit/api/base_controller.rb (L65-80)
```ruby
      def current_user
        @current_user ||= identify_user || AnonymousUser.new
      end

      def identify_user
        user_login = request.headers['X-Shipit-User'].presence
        User.where('lower(login) = ?', user_login.downcase).first if user_login
      end

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
