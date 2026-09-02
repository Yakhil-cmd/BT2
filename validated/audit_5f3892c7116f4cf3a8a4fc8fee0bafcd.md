## Title
Stack-scoped API tokens can read the CCMenu status of any stack, bypassing the client's `stack_id` scope — (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

## Summary
`Shipit::Api::CCMenuController` overrides the `stack` accessor that every other API controller relies on to enforce an `ApiClient`'s stack scope. The override resolves the stack directly from the request parameter instead of going through the scoped `stacks` collection, so a token that is bound to one stack can be replayed against any other stack's endpoint to read its build/deploy status.

## Finding Description
`Shipit::Api::BaseController` defines the authorization-scoping primitive used by every API resource controller: [1](#0-0) 

`stacks` restricts the visible set of stacks to `current_api_client.stack_id` when the client is scoped to a specific stack, and `stack` resolves `params[:stack_id]` only within that restricted collection. This is the binding that authorizes "a stack a token authorises" against "a stack it touches", and it is the mechanism used consistently by `Shipit::Api::StacksController`, `TasksController`, etc.

`CCMenuController`, however, redefines `stack` to bypass this scoping entirely: [2](#0-1) 

Instead of calling the inherited `stacks.from_param!`, it calls `Stack.from_param!(params[:stack_id])` on the unscoped `Stack` model, and `show` then renders that stack's latest deploy/rollback status: [3](#0-2) 

Because `require_permission :read, :stack` only checks that the token carries the `read:stack` permission string (not which stack it is scoped to), and the overridden `stack` method never consults `current_api_client.stack_id`, any authenticated token with `read:stack` — including one created and intended to be scoped to a single stack — can be pointed at an arbitrary `stack_id` to read that stack's CCMenu project state (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `activity`, `webUrl`).

This mirrors the reported bug class exactly: the equality that should hold is `token.authorized_stack == stack_touched_by_request`, and this controller breaks it because the `stack_id` restriction that is verified everywhere else in the API is silently skipped here.

## Impact Explanation
`ApiClient` supports being bound to a single stack via `belongs_to :stack, optional: true` and this scoping is the security boundary enforced by `BaseController#stacks`/`#stack`, and is exercised by the test suite itself: "an api client scoped to a stack will only see that one stack" against `Api::StacksController`. `CCMenuController` is reachable by the same class of token (any token with `read:stack`) yet does not honor that boundary, giving an unauthorized read of another stack's deploy/build state. This matches the High-severity bucket for "escalation ... unauthenticated read of stack state, task streams or deploy output."

## Likelihood Explanation
Any party holding a valid, correctly-authenticated `ApiClient` token with `read:stack` permission — regardless of which single stack it was meant to be scoped to — can trigger this simply by changing the `stack_id` path segment when calling the CCMenu endpoint. No additional secret, signature, or privilege is required beyond possessing one legitimately scoped token.

## Recommendation
Make `CCMenuController#stack` reuse the inherited, scope-aware resolution instead of querying `Stack` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so it is subject to the same `current_api_client.stack_id` restriction enforced in `Api::BaseController`.

## Proof of Concept
1. Create/obtain an `ApiClient` token scoped to `stack_id: A` with `permissions: ['read:stack']` (as supported by the `ApiClient` model and exercised in `test/fixtures/shipit/api_clients.yml`'s `here_come_the_walrus` fixture).
2. Call `GET /api/stacks/A/ccmenu` with that token — succeeds as expected (in-scope stack).
3. Call `GET /api/stacks/B/ccmenu` (a different, unrelated stack) with the same token.
4. Because `CCMenuController#stack` resolves via `Stack.from_param!(params[:stack_id])` and never checks `current_api_client.stack_id`, the request succeeds and returns stack `B`'s build/deploy status, even though the token is only authorized for stack `A`. [4](#0-3) [1](#0-0)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-25)
```ruby
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
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-36)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```
