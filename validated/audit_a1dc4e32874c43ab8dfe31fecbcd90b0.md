### Title
CCMenuController bypasses ApiClient stack scoping, letting a stack-scoped token read any stack's build status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` enforces per-token stack scoping by having every controller resolve stacks through the `stacks`/`stack` helpers, which restrict the queryset to `current_api_client.stack_id` when the token is scoped to a single stack. [1](#0-0)  `Shipit::Api::CCMenuController` overrides `stack` to call `Stack.from_param!` directly instead of `stacks.from_param!`, which bypasses that scoping check entirely. [2](#0-1)  This is the same "authorization binding broken" bug class as the CREATE2 report: the entity that was authorized (a specific stack for a scoped `ApiClient`) is not the entity actually acted upon (`stack` resolves globally across `Stack.all`).

### Finding Description
`ApiClient` tokens can be scoped to a single stack via the `stack_id` column, and `BaseController#stacks` is the mechanism that enforces this scope:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [1](#0-0) 

Every other API controller (`Api::StacksController`, `Api::MergeRequestsController`, `Api::DeploysController`, etc.) relies on this inherited `stack`/`stacks` method, so a token scoped to stack A cannot query stack B — `require_permission!` only checks the `read:stack`/`write:stack` string, the actual stack restriction comes from the `stacks` queryset filter. [3](#0-2) 

`CCMenuController`, however, redefines `stack` to resolve directly against the unscoped `Stack` model:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [4](#0-3) 

Because `require_permission :read, :stack` only calls `current_api_client.check_permissions!('read', 'stack')` — a check on the permission list, not on `stack_id` — any `ApiClient` that has the `read:stack` permission (even one explicitly scoped to a single stack, like the `here_come_the_walrus` fixture) can pass `stack_id` for a **different** stack and the controller will still resolve and render it, because `stack` no longer goes through `stacks.from_param!`.

The equality broken is: `token.authorized_stack == stack_actually_rendered`. Before this bypass, `Api::BaseController#stack` guarantees `token.authorized_stack == stacks.from_param!(...)`. After hitting `CCMenuController#show`, `stack` is resolved from `Stack.from_param!(params[:stack_id])`, i.e., from the full unscoped `Stack` table — breaking that equality for any stack ID an attacker supplies.

### Impact Explanation
This matches the "High" severity category: escalation into `Shipit.github_teams`/stack-level authorization and unauthorized read of stack state. A token intentionally minted with `stack_id` restriction (to give a CI dashboard or CCTray/CCMenu-consuming tool visibility into exactly one stack) can be used to enumerate/read build status (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, lock status) for **any** stack in the Shipit instance, not just the one it was authorized for. This includes stacks belonging to other repositories/teams that the token holder should have no visibility into, which is a genuine cross-boundary read given the multi-tenant nature of a single Shipit deployment serving many teams' stacks.

### Likelihood Explanation
High likelihood: the attacker only needs a valid, currently-issued `ApiClient` token that has `read:stack` permission (even a token deliberately scoped to only one stack) and the ability to change the `stack_id` request parameter — no additional privilege, session, or GitHub credential is required. The `authenticate_api_client` override in `CCMenuController` also allows the token to be passed as a plain `token` query-string parameter (used for CCTray URLs embedded in build dashboards), which increases the likelihood that a "single-stack" token leaks into places where guessing/iterating over other `stack_id` values is straightforward.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` helper inherited from `BaseController`, i.e., `stacks.from_param!(params[:stack_id])`, instead of `Stack.from_param!(params[:stack_id])`, so stack-scoped `ApiClient` tokens cannot be used to read data about stacks they were not authorized for.

### Proof of Concept
1. Create an `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to `stack_A.id` (mirrors the `here_come_the_walrus` fixture pattern). [5](#0-4) 
2. Using that client's `authentication_token`, request `GET /api/:stack_B_owner/:stack_B_name/:env/ccmenu.xml?token=<token>` (or via Basic Auth) for a **different** stack B that the token is not scoped to.
3. Because `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` rather than `stacks.from_param!`, the request succeeds (HTTP 200) and returns stack B's `lastBuildStatus`, `lastBuildLabel`, `activity`, and `webUrl`, even though the token is only supposed to have visibility into stack A per its `stack_id` scoping — contrast with `Api::StacksController#index`, which correctly restricts results to `stack_id`-scoped stacks only, as shown in the existing test "an api client scoped to a stack will only see that one stack". [6](#0-5)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
      end
```
