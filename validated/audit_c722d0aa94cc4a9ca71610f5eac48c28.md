### Title
`Api::CCMenuController` lets a stack-scoped `ApiClient` token read any stack's build/deploy status, not just its authorized stack - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
The bug-class in the referenced report is a mismatch between the value a security check is computed against and the value actually used at execution time (gas allocated for N token IDs vs. gas consumed by the real cross-chain mint/transfer path). The same class of mismatch exists in Shipit's API authorization: the value an `ApiClient` token is *authorized* for (`stack_id`) is not the value actually used to resolve the target resource in `Api::CCMenuController`.

### Finding Description
`Api::BaseController` defines the canonical, scope-respecting resource lookup: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is stack-scoped, and `stack` resolves `params[:stack_id]` against that restricted set — this is how every other API controller (`Api::TasksController`, `Api::HooksController`, etc.) enforces "token authorizes stack X" == "stack touched is X".

`Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely: [2](#0-1) 

It resolves `params[:stack_id]` directly against `Stack.from_param!`, i.e. against *all* stacks, regardless of `current_api_client.stack_id`. The only authorization check applied is `require_permission :read, :stack`: [3](#0-2) 

and `check_permissions!` only verifies the permission string `"read:stack"` is present — it never compares `current_api_client.stack_id` to the requested `stack_id`: [4](#0-3) 

So a token created with `stack_id` set (e.g. the `here_come_the_walrus` fixture, scoped to stack `shipit`) and permission `read:stack` — intended to read only its own stack's status — can instead request `GET /api/stacks/:any_other_stack/ccmenu` and receive that other stack's deploy status, since `Api::CCMenuController#stack` never applies the `stacks` scoping helper.

Binding broken: **stack a token authorizes (`current_api_client.stack_id`) ≠ stack a token touches (`params[:stack_id]` resolved via unscoped `Stack.from_param!`)**.

Before the flaw would matter: every other scoped API endpoint (tasks, hooks, deploys, etc.) uses `stacks.from_param!`, so a stack-scoped token cannot reach data for other stacks. After: `Api::CCMenuController` is the one endpoint where the scoping is silently dropped, letting the same token read arbitrary stacks' build/lock/deploy status.

### Impact Explanation
This is an unauthorized cross-stack read of stack state (deploy status, lock status) using a token that is only supposed to be authorized for one stack — matching the High-impact category of "unauthenticated/unauthorized read of stack state, task streams or deploy output" via a genuine authorization-boundary bypass rather than any missing token, secret, or elevated access.

### Likelihood Explanation
High: any holder of a legitimately-issued, stack-scoped `read:stack` API token (a routine, low-privilege credential explicitly designed to be restricted to one stack) can trivially trigger this by simply changing the `stack_id` path segment on the `ccmenu` route — no additional secrets, session, or privilege escalation needed.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` (or reimplement it using `stacks.from_param!` as in `Api::BaseController`) so that stack-scoped tokens cannot resolve stacks outside `current_api_client.stack_id`.

### Proof of Concept
1. Create an `ApiClient` scoped to stack `shipit` with permission `read:stack` (e.g. fixture `here_come_the_walrus`).
2. Authenticate as that client and issue: `GET /api/stacks/<other-org>/<other-repo>/<other-env>/ccmenu` for a stack the client is not scoped to.
3. `require_permission :read, :stack` passes because the client has the `read:stack` permission string.
4. `Api::CCMenuController#stack` resolves the *other* stack via `Stack.from_param!` (unscoped), and `show` renders that stack's CCMenu XML (build/deploy/lock status) even though the token's `stack_id` binds it only to `shipit`. [5](#0-4)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
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
