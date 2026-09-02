### Title
API stack-scoping bypass in `Api::CCMenuController` allows a stack-scoped token to read any stack's build status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::ApiClient` tokens can be scoped to a single stack via `ApiClient#stack_id`, and the API base controller enforces that scoping through the `stacks`/`stack` helper methods. `Api::CCMenuController` overrides `stack` and bypasses this scoping, so a token that is authorized (`read:stack`) for one specific stack can be replayed with a different `stack_id` to read the CI/deploy status of any other stack in the installation.

### Finding Description
`Api::BaseController` defines the trust binding between a token and the stacks it may touch: [1](#0-0) 

`current_api_client.stack_id?` restricts the `stacks` relation to the single stack the `ApiClient` was scoped to when created (see the `here_come_the_walrus` fixture, which is scoped to `stack: shipit`): [2](#0-1) 

`require_permission` only checks that the client's permission list contains the string `"read:stack"` / `"deploy:stack"`, etc. — it performs no per-stack check: [3](#0-2) 

So the *only* place enforcing "this token may only see the stack it was scoped to" is the `stack`/`stacks` helper in `BaseController`. Every other controller (`DeploysController`, `TasksController`, `MergeRequestsController`, `RollbacksController`, `HooksController`, etc.) relies on the inherited `stack` method and is therefore correctly scoped.

`Api::CCMenuController`, however, defines its own `stack` method that talks to `Stack` directly, completely skipping the `stacks` scoping: [4](#0-3) 

This breaks the equality that should hold: `stack a token authorizes == stack a token touches`. A token scoped to stack A (permission `read:stack` for stack A only) can supply `stack_id` for stack B in the request path and `CCMenuController#show` will happily resolve and render stack B's `deploy`/`activity`/`lastBuildStatus` data: [5](#0-4) 

The controller also supports authenticating via a `?token=` query-string parameter (in addition to Basic auth), which is exactly the same token format used elsewhere, so this is trivially reachable by any holder of a scoped `read:stack` token (e.g., a CI system or CCMenu widget operator that was only ever meant to see one stack): [6](#0-5) 

### Impact Explanation
This is an unauthenticated-for-other-stacks / unauthorized read of stack state: a legitimately-issued, narrowly-scoped API token (holding only `read:stack` for stack A) can be used to enumerate and read the CI/build/deploy status (`activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) of every other stack managed by the Shipit instance, including stacks belonging to different repositories/teams that the token holder was never granted access to. This matches the "High" impact category of unauthenticated read of stack state.

### Likelihood Explanation
High likelihood: exploitation requires nothing more than a valid, narrowly-scoped `ApiClient` token (which is intentionally distributed to third parties/CI tools for the CCMenu integration) and knowledge/guessing of another stack's `owner/repo/environment` identifier (which is often predictable or discoverable, e.g. from the CCMenu URL scheme `owner/repo/environment`). No privileged access, signing key, or session is required beyond possessing one legitimately scoped token.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the inherited, scope-respecting `stacks` helper instead of querying `Stack` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
and remove the private override entirely (falling back to `BaseController#stack`). Additionally, consider auditing all controllers under `app/controllers/shipit/api/**` for similar direct `Stack.from_param!`/`Stack.find` calls that bypass the `stacks` scoping helper.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_id: <stack A id>` with permission `read:stack` (as in fixture `here_come_the_walrus`).
2. As the holder of that token, issue:
   ```
   GET /api/stacks/<owner>/<other-repo>/<other-env>/ccmenu?token=<scoped_token>
   ```
   substituting a stack B that the token was never scoped to.
3. Observe HTTP 200 with a full CCMenu XML payload (`lastBuildStatus`, `activity`, etc.) for stack B, even though `check_permissions!` only validated the generic `read:stack` string and `stack` bypassed the `current_api_client.stack_id` restriction that governs every other API endpoint.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
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
