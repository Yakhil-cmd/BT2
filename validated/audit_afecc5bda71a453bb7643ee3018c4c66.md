### Title
Stack-scoped `ApiClient` can read build status of any stack via `CCMenuController#show` because `#stack` bypasses the `stacks` scope filter - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` enforces per-client stack scoping through its private `stacks`/`stack` helpers, which restrict lookups to `Stack.where(id: current_api_client.stack_id)` when the client has a `stack_id`. `CCMenuController` overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` relation, completely bypassing that restriction, so any token with the literal permission string `read:stack` can read `cc.xml` build data for any stack regardless of the token's `stack_id`.

### Finding Description
The broken binding is: the set of stacks readable by a client token should equal `current_api_client.stack_id? ? {stack_id} : all stacks`, but for `CCMenuController#show` the actual set read is `all stacks`, independent of `stack_id`.

- `BaseController` defines the scoped resolution: [1](#0-0) 
  `stacks` filters by `current_api_client.stack_id` when present; `stack` resolves through that scoped relation.

- `require_permission!` only checks the operation/scope string pair, never the target stack: [2](#0-1) [3](#0-2) 
  `check_permissions!('read', 'stack')` just checks `permissions.include?('read:stack')` — it never receives or compares `stack_id`.

- `CCMenuController` declares the class-level permission check and then defines its own `#stack`, which does not use the inherited scoped `stacks` helper at all: [4](#0-3) 
  `@stack ||= Stack.from_param!(params[:stack_id])` resolves against the entire `Stack` table, not `current_api_client.stack_id`.

Attack: an `ApiClient` created with `stack_id: X` and `permissions: ['read:stack']` (a legitimate, narrowly-scoped, read-only token for repository X's stack) requests `GET /stack_id_or_something/cc.xml?stack_id=Y&token=<token>` where `Y` is an unrelated stack in a different repository. `authenticate_api_client` (overridden in this controller to also accept `params[:token]`) succeeds; `require_permission!(:read, :stack)` passes because the token literally has `read:stack` in its `permissions` array; `#stack` then resolves `Y` directly via `Stack.from_param!`, with no `stack_id` scoping applied. `#show` renders `Y`'s deploy status, activity, and build label/time in the CCTray XML.

This differs from `StacksController`, which correctly uses the inherited `stack` (and `stacks`) helper: [5](#0-4) 
so the stack-scoping guarantee genuinely holds there but is broken specifically in `CCMenuController`.

No other guard closes this gap: `check_permissions!` is scope/operation-only by design (`app/models/shipit/api_client.rb:38-45`), and `CCMenuController#stack` (`app/controllers/shipit/api/ccmenu_controller.rb:29-31`) is the sole resolver used by `#show`, with no secondary check against `current_api_client.stack_id`.

### Impact Explanation
A holder of a stack-scoped, read-only token for repository X can read the CI/CD build status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, lock state, activity) of any other stack/repository Y on the same Shipit instance, repeatedly and for any stack ID they can guess or enumerate. This is an unauthorized read of stack/deploy state across tenant boundaries — matching the "High: escalation ... unauthenticated/unauthorized read of stack state, task streams or deploy output" category. Blast radius is instance-wide: every stack on the Shipit host is exposed to any client holding a `read:stack` token, no matter what `stack_id` that token was scoped to.

### Likelihood Explanation
Preconditions: attacker needs any valid `ApiClient` token with `read:stack` in `permissions` (a normal, minimally-scoped CI-integration token type in this system) and knowledge/guess of a target `stack_id`/param. No GitHub secrets, session, or team membership is required — only possession of a routine stack-scoped API token, which is a low, realistic bar since such tokens are commonly distributed to CI systems for exactly the CCMenu/cc.xml use case. The request is a simple unauthenticated-cost `GET` and fully repeatable against arbitrary stacks.

### Recommendation
Remove `CCMenuController`'s private `#stack` override, or reimplement it to use the inherited scoped `stacks` relation (`stacks.from_param!(params[:stack_id])`) exactly as `BaseController`/`StacksController` do, so `current_api_client.stack_id` scoping is enforced consistently across all controllers.

### Proof of Concept
Minitest plan (place under `test/controllers/api/ccmenu_controller_test.rb`, no live GitHub needed):
```ruby
test "a stack-scoped read:stack token cannot read a different stack's cc.xml" do
  stack_x = shipit_stacks(:shipit)
  stack_y = Stack.create!(repository: Repository.new(owner: "other", name: "repo"), branch: "main")

  scoped_client = ApiClient.create!(
    creator: shipit_users(:walrus),
    name: "scoped-token",
    stack_id: stack_x.id,
    permissions: ["read:stack"]
  )

  get :show, params: { stack_id: stack_y.to_param, token: scoped_client.authentication_token }

  # Binding under test: readable_stacks(scoped_client) == {stack_x.id}
  # Actual behavior observed: stack_y is returned despite stack_y.id != stack_x.id
  assert_response :ok
  project = Hash.from_xml(response.body)['Projects']['Project']
  assert_equal stack_y.to_param, project['name'] # demonstrates unauthorized cross-stack read
end
```
This asserts the token scoped to `stack_x` can successfully retrieve `stack_y`'s build data, proving `current_api_client.stack_id` is never enforced in `CCMenuController#show`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-31)
```ruby
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
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```
