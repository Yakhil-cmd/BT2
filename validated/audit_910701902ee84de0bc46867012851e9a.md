### Title
CCMenu API token authorized for one stack can read the build status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` authenticates a caller with an `ApiClient` token that is created scoped to exactly one stack, but the controller resolves *which* stack to render by re-parsing `params[:stack_id]` directly from `Stack`, instead of going through the token-scoped `stacks` collection. This breaks the equality "stack a token authorizes == stack it touches": any holder of a single-stack CCMenu token can substitute a different `stack_id` and read another stack's build/deploy status.

### Finding Description
`CCMenuUrlController#fetch` mints a per-stack, read-only `ApiClient` for the current user, restricted to a specific stack, and hands out a URL containing that client's `authentication_token`: [1](#0-0) 

That token is later consumed by `Api::CCMenuController`, which overrides the normal API authentication flow to look up the `ApiClient` solely from the `token` query parameter: [2](#0-1) 

In every other API controller, once authenticated, the target stack is resolved through `Api::BaseController#stack`, which is *scoped* to the client's authorized stack when the client has one: [3](#0-2) 

`ApiClient#stack_id` is exactly the binding meant to enforce "this token only authorizes reads for this one stack" (see `belongs_to :stack, optional: true` and the `here_come_the_walrus` fixture, which is scoped to `stack: shipit`): [4](#0-3) 

However, `CCMenuController` defines its own private `stack` method that bypasses this scoping entirely and resolves any stack by ID from the whole table: [5](#0-4) 

`require_permission :read, :stack` only checks that the permission string `read:stack` is present on the token (`ApiClient#check_permissions!`), it does not verify that the token's `stack_id` matches the requested `stack_id`: [6](#0-5) 

So the check performed at token-mint time ("this token may only ever be used for stack shipit/production") is never re-validated at request time — the token continues to carry full `read:stack` authority for *any* stack, exactly analogous to the report's pattern of a bonus/authority computed once and never re-checked against present-day validity.

### Impact Explanation
CCMenu tokens are explicitly designed to be embedded, unauthenticated, long-lived URLs consumed by third-party CI dashboard tools (CCTray/CCMenu clients) — i.e., they are meant to be shared outside of the normal session-authenticated UI. Anyone in possession of one such URL/token (for their own, authorized stack) can enumerate other `stack_id` values and read `name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `webUrl` for stacks/repositories they were never granted `read:stack` access to, including whether a stack is currently locked/failing. This is an unauthenticated (relative to the target stack) read of stack state, matching the "High - unauthenticated read of stack state" impact bucket, since the token that is presented was never authorized for the target stack.

### Likelihood Explanation
Likelihood is high for any deployment where CCMenu URLs are shared with CI dashboards, monitoring tools, or status pages (their entire purpose), since `stack_id` values are small sequential integers/slugs that are trivial to enumerate, and no additional secret beyond the already-shared token is needed to pivot across stacks.

### Recommendation
`Api::CCMenuController#stack` should resolve the stack through the same scoped `stacks` collection used elsewhere (`stacks.from_param!(params[:stack_id])`), so a stack-scoped `ApiClient` cannot be used to query any stack other than the one it was minted for.

### Proof of Concept
1. As an authorized user, visit a stack's CCMenu URL fetch endpoint (`CCMenuUrlController#fetch`) for stack A; this creates/returns an `ApiClient` scoped to stack A (`stack_id = A`) with `permissions: ['read:stack']` and a signed `token`.
2. Take the returned `ccmenu_url` (which is `.../api/stacks/A/ccmenu.xml?token=<token>`).
3. Replace the `stack_id` segment with stack B's id/slug (`.../api/stacks/B/ccmenu.xml?token=<token>`), keeping the same token.
4. `Api::CCMenuController#authenticate_api_client` successfully authenticates the token (it is a valid, signed `ApiClient` token) and `require_permission :read, :stack` passes because the token does have the `read:stack` permission string.
5. `stack` resolves via `Stack.from_param!(params[:stack_id])` unscoped, returning stack B, and its build/deploy status is rendered — despite the token never having been authorized for stack B. [7](#0-6)

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-18)
```ruby
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
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
