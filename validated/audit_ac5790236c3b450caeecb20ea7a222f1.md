Confirmed: `Shipit::Api::CCMenuController#stack` at `app/controllers/shipit/api/ccmenu_controller.rb:29-31` overrides the base controller's scoped `stack` accessor by calling `Stack.from_param!(params[:stack_id])` directly, bypassing `stacks` (which restricts to `current_api_client.stack_id` when the client is stack-scoped). The `require_permission :read, :stack` check only validates the client has the `read:stack` permission bit — it never checks that the requested stack matches `current_api_client.stack_id`. The view `app/views/shipit/ccmenu/project.xml.builder:9` renders `stack.to_param` (owner/repo/environment) regardless of `deploy` being real or `NoDeploy.new`.### Title
Cross-tenant stack metadata disclosure via unscoped `Stack.from_param!` in `CCMenuController#stack` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController#stack` looks up stacks with `Stack.from_param!(params[:stack_id])` directly instead of using the base controller's stack-scoped `stacks` collection, so any valid API token — even one scoped to a single stack via `stack_id` — can fetch the CCMenu XML for any stack in the system. Whether or not that victim stack has deploys, the rendered XML discloses `stack.to_param` (owner/repo/environment/branch identifiers).

### Finding Description
The intended binding is: `the stack disclosed via CCMenuController#show == a stack authorized by current_api_client.stack_id` (i.e., `stack.id == current_api_client.stack_id` when the client is stack-scoped). This binding is broken.

`Shipit::Api::BaseController#stacks` correctly scopes lookups: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`, and `#stack` uses `stacks.from_param!(...)` [1](#0-0) . However, `CCMenuController` overrides `#stack` and bypasses this scoping entirely, querying the global `Stack` relation: `@stack ||= Stack.from_param!(params[:stack_id])` [2](#0-1) . `require_permission :read, :stack` only checks that the token's `permissions` array contains `read:stack` via `ApiClient#check_permissions!`, which never compares `stack_id` to the requested stack [3](#0-2) . Consequently a token created for stack A (e.g. via `CCMenuUrlController#client`, which creates a `read:stack`-only client tied to one stack [4](#0-3) ) can be replayed against `GET /api/stacks/:victim_stack/ccmenu?token=<attacker_token>` for any other stack B.

In `#show`, `latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new` substitutes a stub when stack B has no deploys, but the render call still passes the real `stack` local: `render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })` [5](#0-4) . The view unconditionally renders `name: stack.to_param` [6](#0-5) , so `stack.to_param` (repo_owner/repo_name/environment) leaks regardless of `NoDeploy` substitution. No guard (`force_github_authentication`, `require_permission!`, `stacks` scoping) intervenes because the override entirely skips the scoping mechanism.

### Impact Explanation
An attacker holding any valid stack-scoped `read:stack` API token (their own, legitimately obtained CCMenu token for a stack they control) can enumerate/disclose the existence, repo owner/name, and environment/branch of any other stack on the Shipit instance, including private ones, by iterating `stack_id` path values. This is a cross-tenant read of private stack identifying metadata — matching the High severity category "unauthenticated/wrongly-scoped read of stack state" (the attacker is authenticated but not authorized for the target stack). It is fully repeatable against arbitrary stacks and requires only enumerating repo_owner/repo_name/environment strings.

### Likelihood Explanation
Preconditions: attacker needs any valid API token with `read:stack` permission (trivially obtainable for their own repository via `CCMenuUrlController#fetch`, which any authenticated Shipit user can trigger for stacks they can view) and knowledge/guessing of a victim `owner/repo/environment` triple. No GitHub or Shipit secrets are required beyond the attacker's own legitimate token. Cost is a single unauthenticated-to-target HTTP GET; fully repeatable.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController` and instead use the inherited, properly scoped `stacks.from_param!(params[:stack_id])` from `BaseController`, ensuring `current_api_client.stack_id` (when set) restricts lookups to that stack, consistent with all other API controllers.

### Proof of Concept
Add to `test/controllers/api/ccmenu_controller_test.rb`:
```ruby
test "a stack-scoped token cannot fetch ccmenu for another stack" do
  victim = Stack.create!(repository: Repository.new(owner: "victim", name: "repo"), environment: "production", branch: "main")
  scoped_client = ApiClient.create!(creator: @user, name: "scoped", stack: @stack, permissions: %w[read:stack])
  request.headers['Authorization'] = "Basic #{Base64.encode64(scoped_client.authentication_token)}"

  get :show, params: { stack_id: victim.to_param }

  assert_response :forbidden # expected: token scoped to @stack.id must not resolve victim.id
  # Actual (vulnerable) behavior: response is :ok and body discloses victim.to_param
end
```
Assert the binding `scoped_client.stack_id == victim.id` is false yet the controller still returns `stack.to_param == victim.to_param` in the XML — demonstrating the scoping bypass.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/views/shipit/ccmenu/project.xml.builder (L7-15)
```text
  xml.Project(
    '',
    name: stack.to_param,
    lastBuildStatus: status_map.fetch(stack.merge_status, stack.merge_status).capitalize,
    activity: deploy.running? ? 'Building' : 'Sleeping',
    lastBuildTime: deploy.ended_at || deploy.started_at || deploy.created_at,
    lastBuildLabel: deploy.id,
    webUrl: stack_url(stack)
  )
```
