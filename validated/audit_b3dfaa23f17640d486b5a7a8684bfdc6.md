### Title
Cross-Stack Read via `Api::CCMenuController#stack` Bypasses ApiClient Stack Scoping - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::CCMenuController` overrides the `stack` accessor inherited from `Api::BaseController` in a way that drops the scoping enforced by an `ApiClient`'s `stack_id`. This breaks the binding "a stack a token authorizes == a stack it touches": a token minted for one stack can be used to read the CCMenu/CCTray status (project name, activity, last build result) of any other stack in the deployment.

### Finding Description
`Api::BaseController` defines stack access scoped to the authenticated `ApiClient`: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is stack-scoped, and `stack` resolves `params[:stack_id]` only within that restricted relation via `stacks.from_param!`. This is the mechanism the engine relies on to bind an `ApiClient`'s authorization to a single stack.

`Api::CCMenuController`, however, defines its own `stack` method that ignores this scoping entirely and resolves the parameter against the full `Stack` table: [2](#0-1) 

The controller still declares `require_permission :read, :stack`: [3](#0-2) 

but `require_permission!`/`check_permissions!` only checks that the `read:stack` permission string is present in `ApiClient#permissions` — it never checks whether the requested `stack_id` matches the token's bound `stack_id`: [4](#0-3) [5](#0-4) 

So the only place that binding "token authorizes stack X" is enforced is `BaseController#stack`, via the `stacks` scoping — and `CCMenuController` bypasses exactly that method.

Route confirmation — the `ccmenu` action accepts an arbitrary `stack_id` path segment: [6](#0-5) 

### Impact Explanation
An `ApiClient` created with `stack_id` set (i.e., explicitly scoped to a single stack, e.g. the `here_come_the_walrus` fixture) and only granted `read:stack`: [7](#0-6) 

is expected to be able to read state only for its bound stack. Because `Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!`, that same token can be presented with any other stack's `stack_id` in the URL and receive that stack's CCTray/CCMenu XML (project name/activity/last build status) rendered by `shipit/ccmenu/project.xml.builder`. This is an authorization-scope escalation: the token authorizes reads for one stack, but the endpoint lets it touch (read) any stack. This matches the "High — escalation into `Shipit.github_teams` authorization … unauthenticated read of stack state" impact category, since it grants read of deploy/stack state outside the token's authorized boundary.

### Likelihood Explanation
Any holder of a legitimate, narrowly-scoped `ApiClient` token (a routine, unprivileged credential intentionally restricted to one stack) can trivially trigger this by changing the `stack_id` path segment on the `GET /api/stacks/:stack_id/ccmenu` request — no additional privilege, guessing of secrets, or race condition is required. The only prerequisite is possession of any valid stack-scoped `read:stack` token, which is the exact "unprivileged attacker" scenario contemplated by the scan rules (an ApiClient token is allowed as the attacker's starting credential since the vulnerability is about the token exceeding its own authorized scope).

### Recommendation
Remove the `CCMenuController#stack` override, or reimplement it to resolve `params[:stack_id]` through the inherited `stacks` scoping (`stacks.from_param!(params[:stack_id])`) so stack-scoped `ApiClient` tokens cannot read CCMenu data for stacks outside their `stack_id` binding.

### Proof of Concept
1. Create (or use) an `ApiClient` scoped to `stack_id = A` with permission `read:stack` (e.g. fixture `here_come_the_walrus`, scoped to stack `shipit`).
2. Authenticate as that client and request:
   `GET /api/stacks/<other-owner>/<other-repo>/<other-env>/ccmenu`
   where the path identifies a different stack `B` that the client is not scoped to.
3. `Api::CCMenuController#authenticate_api_client` succeeds (valid token), `require_permission :read, :stack` passes (`read:stack` is in permissions), and `stack` resolves via `Stack.from_param!(params[:stack_id])` against the entire `Stack` table, returning stack `B`.
4. The controller renders `shipit/ccmenu/project.xml.builder` for stack `B`, returning stack `B`'s CCTray project name/activity/last build status even though the token is only authorized for stack `A`. [8](#0-7)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-8)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack

      class NoDeploy
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
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

**File:** config/routes.rb (L27-29)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
      resource :lock, only: %i[create update destroy]
```

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```
