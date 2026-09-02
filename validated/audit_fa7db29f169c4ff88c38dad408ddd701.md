### Title
Stack-scoped API tokens bypass their `stack_id` restriction in the CCMenu endpoint, allowing cross-stack unauthorized read of deploy state - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` scopes the set of stacks an `ApiClient` may act on to `current_api_client.stack_id` when the client is bound to a specific stack, via the `stacks`/`stack` helper methods. [1](#0-0)  `Shipit::Api::CCMenuController` overrides `stack` to resolve directly from `Stack.from_param!(params[:stack_id])`, never consulting `current_api_client.stack_id`, so the scoping binding that every other API controller relies on is silently dropped for this endpoint. [2](#0-1) 

### Finding Description
The intended trust binding is: **`ApiClient.stack_id` (the stack a token authorizes) == the stack the request is allowed to touch**. `BaseController#stacks` encodes this: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`, and `BaseController#stack` resolves the requested stack only from that restricted relation (`stacks.from_param!(params[:stack_id])`). [1](#0-0) 

`CCMenuController` (used to serve a CI-status XML feed, e.g. for CCMenu clients) authenticates the `ApiClient` from a `token` request parameter instead of an `Authorization` header, then checks only the generic `read:stack` permission via `require_permission :read, :stack`. [3](#0-2) [4](#0-3)  Critically, it redefines `stack` as:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```
which looks up **any** stack by `params[:stack_id]`, completely bypassing the `stacks` scoping helper that binds the lookup to `current_api_client.stack_id`. [5](#0-4) 

This is exactly the bug class in the report generalized to authorization state: the report shows a governing invariant (`adjustedTotalSupply` = totalSupply − timelock balance) that silently drifts because one code path (the timelock migration) updates only one side of the binding (`ds.timelock`) while leaving the other side (token custody) untouched. Here the analogous invariant is `client-authorized stack == accessed stack`; `BaseController` updates/enforces both sides consistently, but `CCMenuController` updates only the authentication side (via `authenticate_api_client`) while its `stack` resolver silently drops the second half of the binding (the `stack_id` scope check), producing the same “one side changed, one side not” inconsistency.

**Before**: a stack-scoped `ApiClient` (e.g. `here_come_the_walrus` fixture, which has `stack: shipit` and only `read:stack` permission) can only see the one stack it's bound to, as enforced everywhere else in the API (e.g. `StacksController#index` restricts to `stacks`, and the existing test "an api client scoped to a stack will only see that one stack" confirms this behavior for `StacksController`). [6](#0-5) [7](#0-6) 

**After**: using that same scoped token's `authentication_token` as the `token` query param against `CCMenuController#show` with an arbitrary `stack_id` for a different stack, the request passes `authenticate_api_client` (token is valid) and `require_permission!(:read, :stack)` (client has that generic permission), and `stack` resolves the *other* stack directly, rendering its latest deploy/rollback status and stack name in the XML response. [8](#0-7) 

### Impact Explanation
This is an unauthenticated-relative-to-scope, unauthorized read of stack state: a low-privilege, single-stack-scoped API token can read CI/deploy status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, stack name) for any other stack in the Shipit instance, not just the one it was provisioned for. This matches the High-severity category "unauthenticated read of stack state, task streams or deploy output" defined in scope, since it escalates a token's authorization boundary (one stack) to read data belonging to arbitrary other stacks/repositories the token holder has no legitimate access to.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped `ApiClient` tokens (a supported, documented feature — see `ccmenu_url_controller.rb`, which creates exactly such a scoped client via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(...)`). [9](#0-8)  Any holder of a legitimately-issued, stack-scoped CCMenu token (which is handed out fairly liberally as a "read-only CI status" URL) can trivially swap the `stack_id` query parameter to enumerate other stacks — no privileged account or session is required beyond possessing one such token, which is explicitly the class of unprivileged-attacker capability this scan is scoped to include.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the scoped `stacks` helper inherited from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so that a stack-scoped `ApiClient`'s `stack_id` binding is enforced consistently with every other API controller.

### Proof of Concept
1. Provision two stacks, `A` and `B`.
2. Create (or use) an `ApiClient` scoped to stack `A` only, with `permissions: ['read:stack']` (mirrors `here_come_the_walrus` fixture / the client created by `CCMenuUrlController#client`). [7](#0-6) [9](#0-8) 
3. Obtain its `authentication_token` (as done via `CCMenuUrlController#fetch`, which legitimately exposes this token to anyone with access to stack `A`'s CCMenu URL). [10](#0-9) 
4. Issue `GET /api/stacks/B/repo_owner/repo_name/environment/ccmenu.xml?token=<A's token>` (i.e. the CCMenu endpoint with `params[:stack_id]` pointing at stack `B`).
5. `authenticate_api_client` succeeds (token is valid), `require_permission!(:read, :stack)` succeeds (client has `read:stack`), and `stack` resolves stack `B` directly via `Stack.from_param!`, returning `B`'s deploy status XML — despite the token being scoped only to `A`. [11](#0-10)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-39)
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
  end
end
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-11)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end
```
