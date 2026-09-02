### Title
Scoped API client token authorizes reads of any stack's build status, not just the stack it was issued for - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` authenticates a request using a bare `ApiClient` token from the query string and checks only that the client has the `read:stack` permission, but then resolves the target stack via an unscoped lookup (`Stack.from_param!`) instead of the client's own stack scope. This breaks the binding "the stack a token authorizes" == "the stack it touches," letting the holder of any stack-scoped CCMenu token read the build status of every other stack in the installation.

### Finding Description
`Api::BaseController` defines the canonical, safe pattern for resolving the target stack for a scoped `ApiClient`: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the api client is scoped to a specific stack, and `stack` resolves `params[:stack_id]` only within that restricted scope. This is the binding: a stack-scoped token may only ever touch the stack it was created for.

`Api::CCMenuController`, however, overrides both `stack` and `authenticate_api_client`: [2](#0-1) 

Two things diverge from the trusted pattern:
1. `authenticate_api_client` authenticates the client from `params[:token]` directly (bypassing HTTP Basic auth, intended for embeddable CCMenu URLs), which is expected.
2. `stack` calls `Stack.from_param!(params[:stack_id])` directly on the `Stack` model — the *global*, unscoped table — rather than `stacks.from_param!(params[:stack_id])` used everywhere else in the API. `require_permission :read, :stack` only verifies that the authenticated client's `permissions` array contains `read:stack`; it never checks that `current_api_client.stack_id` matches the requested `stack_id`.

As a result, `check_permissions!` in `ApiClient` only validates the permission string, never the stack scope: [3](#0-2) 

These CCMenu tokens are specifically designed to be embedded in a shareable, unauthenticated URL for CI tray tools: [4](#0-3) 

Any holder of one such URL/token — which is explicitly meant to be handed out to third-party polling tools and thus has a much wider exposure surface than a typical API credential — can swap the `stack_id` in the URL and read the status of any stack, including private/production stacks they were never granted access to.

### Impact Explanation
This is an authorization boundary break scoped exactly to the "stack a token authorizes vs. stack it touches" trust binding called out in scope. The impact is unauthenticated read of stack state/deploy status for stacks the token holder has no legitimate access to (`stack.deploys_and_rollbacks.last`, build name, last build label/status/time). This matches the accepted High-impact category: "unauthenticated read of stack state, task streams or deploy output."

### Likelihood Explanation
Medium-to-high. Exploitation only requires possession of any single scoped CCMenu token (which by design is distributed via a plain, unauthenticated URL meant for third-party CI tray applications) and knowledge/enumeration of another stack's `stack_id` (owner/name/environment/branch, which is often public information visible in the Shipit UI, GitHub repo names, etc.). No privileged Shipit session or GitHub credentials are required — only a leaked/shared CCMenu URL, which is the class of URL Shipit explicitly designs to be shared with external tools.

### Recommendation
In `Api::CCMenuController#stack`, resolve the stack through the same client-scoped lookup used elsewhere in the API (`stacks.from_param!(params[:stack_id])`, inherited/overridable from `BaseController`) instead of `Stack.from_param!(params[:stack_id])`, so a stack-scoped token can only ever resolve to the stack it was created for.

### Proof of Concept
1. A legitimate user visits stack A and calls `CCMenuUrlController#fetch`, which creates an `ApiClient` scoped to stack A with `permissions: %w[read:stack]` and returns a CCMenu URL containing `token=<A's token>`. [5](#0-4) 
2. This URL is shared with (or leaked to) a third party, or embedded in a CI tray tool config, as it is intended to be used without any additional authentication.
3. An attacker in possession of this URL/token requests `GET /api/stacks/<other-org>/<other-repo>/<other-env>/ccmenu?token=<A's token>` — substituting the `stack_id` of a different stack B they were never authorized for.
4. `authenticate_api_client` succeeds because the token is valid for `ApiClient` A. `require_permission :read, :stack` succeeds because A's `permissions` includes `read:stack`. `stack` resolves via `Stack.from_param!(params[:stack_id])`, which is unscoped and returns stack B regardless of A's `stack_id`.
5. The controller renders stack B's build name, last build status/label/time — data the attacker was never authorized to read. [6](#0-5)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-37)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L1-23)
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
```
