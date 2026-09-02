### Title
Api::CCMenuController#stack bypasses `current_api_client.stack_id` scoping, exposing any stack's deploy status to any `read:stack` token - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` enforces per-token stack scoping through the `stacks` helper (`Stack.where(id: current_api_client.stack_id)` when `stack_id?` is set) before resolving `params[:stack_id]`. `Shipit::Api::CCMenuController` overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, completely skipping that authorization filter, so any token with the generic `read:stack` permission can fetch `cc.xml` for any stack in the installation.

### Finding Description
The binding claimed to hold is: `stack resolvable for params[:stack_id] == B  ⇒  B ∈ Stack.where(id: current_api_client.stack_id)`.

In `Shipit::Api::BaseController`: [1](#0-0) 
`stacks` restricts the queryable set to the client's authorized stack(s) when `current_api_client.stack_id?` is true, and `stack` resolves through that scoped relation.

`Shipit::Api::CCMenuController`, however, redefines `stack` independently: [2](#0-1) 
It calls `Stack.from_param!(params[:stack_id])` on the bare `Stack` class instead of the scoped `stacks` relation inherited from the base controller. The `before_action` guard is only `require_permission :read, :stack`, which calls `ApiClient#check_permissions!`: [3](#0-2) 
`check_permissions!` only checks membership in the token's `permissions` array (e.g. `"read:stack"`); it never inspects `stack_id` or compares it against the requested `params[:stack_id]`. Because `Api::CCMenuController#stack` never routes through the scoped `stacks` method, the equality above never gets evaluated for this action — the divergence is real.

Attacker flow: an attacker obtains a legitimately-issued CCMenu token for stack A (e.g. via `CCMenuUrlController#fetch`, which creates an `ApiClient` with only `permissions: %w[read:stack]` and no `stack_id` restriction unless one is separately set) then issues `GET /api/stacks/:B/cc.xml?token=<token-for-A>` (or any stack B's `stack_id`) and receives the full CCMenu XML for stack B, including `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime` derived from `stack.deploys_and_rollbacks.last`.

No existing guard prevents this: `require_permission!` checks only the flat permission string, not the stack scope; the `stacks` scoping helper that would enforce it is bypassed by the controller-local `stack` override.

### Impact Explanation
Any holder of a `read:stack`-scoped API token (regardless of the `stack_id` it was minted for) can enumerate and read deploy status/timing (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, activity) for arbitrary stacks, including ones backed by private repositories the token was never scoped to and that the attacker cannot see on GitHub. This is repeatable against every stack ID in the installation and constitutes unauthenticated (relative to the target stack) cross-tenant disclosure of stack existence and deploy state — matching the High severity category "escalation into ... unauthenticated read of stack state."

### Likelihood Explanation
Precondition: the attacker must hold at least one valid `ApiClient` token carrying `read:stack` permission (obtainable legitimately for any stack they do have access to, e.g. via the normal CCMenu URL feature on a stack settings page). No GitHub access to the target stack's repository, no Shipit session, and no knowledge of `api_clients_secret` is needed beyond the attacker's own token. `stack_id` values are small sequential integers or predictable slugs (`Stack.from_param!` typically resolves `owner/repo/branch` or numeric id), making enumeration trivial. Cost is a single authenticated GET request per target stack, fully repeatable.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the inherited, scoped `stacks` relation instead of the bare `Stack` class:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
and remove the private override entirely so the base controller's scoped implementation is used, or explicitly check `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id` before rendering.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a token scoped to stack A cannot read cc.xml for stack B" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "private-org", name: "secret-repo"), branch: 'main')
  Deploy.create!(stack: stack_b, until_commit: shipit_commits(:first), since_commit: shipit_commits(:first), status: 'success')

  scoped_client = ApiClient.create!(creator: @user, name: 'Scoped', permissions: %w[read:stack], stack_id: stack_a.id)

  get :show, params: { stack_id: stack_b.to_param, token: scoped_client.authentication_token }

  # Binding under test: stack_b.id ∈ Stack.where(id: scoped_client.stack_id) is false
  assert_not_includes Stack.where(id: scoped_client.stack_id).pluck(:id), stack_b.id
  # But the controller still renders stack_b's real deploy data instead of 403/404:
  assert_response :ok
  project = Hash.from_xml(response.body)['Projects']['Project']
  assert_equal stack_b.to_param, project['name']
  assert_equal 'Success', project['lastBuildStatus']
end
```

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
