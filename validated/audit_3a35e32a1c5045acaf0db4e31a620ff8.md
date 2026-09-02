### Title
CCMenu API tokens are never scoped to their originating stack, allowing a leaked CCMenu URL to read any stack's build status - ([File: app/controllers/shipit/ccmenu_url_controller.rb, app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The "Fetch URL" feature that mints a CCMenu token for a specific stack (`CCMenuUrlController#client`) never associates the created `ApiClient` with that stack, and `CCMenuController` additionally resolves the target stack with an unscoped `Stack.from_param!(params[:stack_id])` instead of the scope-respecting `stacks.from_param!` used elsewhere. As a result, any leaked `params[:token]` from one stack's CCMenu URL can be replayed against `/api/stacks/<any_other_stack_id>/ccmenu` and will succeed.

### Finding Description
The claimed binding should be: `requested_stack.id == current_api_client.stack_id` (the stack the request touches must be the one the token authorizes), exactly as `BaseController` enforces for every other API endpoint via `stacks` / `stack`: [1](#0-0) 

`CCMenuController`, however, overrides both halves of that enforcement:
1. `authenticate_api_client` authenticates directly off `params[:token]` (bypassing the shared `authenticate_api_client`, which is fine since it's a public-token endpoint by design): [2](#0-1) 
2. Crucially, `stack` is overridden to `Stack.from_param!(params[:stack_id])` — completely bypassing the `stacks` scope that would restrict lookups to `current_api_client.stack_id`: [3](#0-2) 

Compounding this, the token itself is never scoped to a stack in the first place. `CCMenuUrlController#client` finds-or-creates the `ApiClient` keyed only on `creator` and a fixed `name: 'CCMenu Client'`, never passing `stack:`: [4](#0-3) 

This differs from the intended pattern demonstrated by the `here_come_the_walrus` fixture, where a scoped client explicitly sets `stack: shipit`: [5](#0-4) 

Because `stack:` is never set, `current_api_client.stack_id?` is false for every CCMenu token, so even the (bypassed) `stacks` scope in `BaseController` would return `Stack.all`, not just the originating stack: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`. Only the `read:stack` permission is checked via `require_permission :read, :stack`, not any per-stack identity check.

Attacker flow: obtain any leaked CCMenu URL, e.g. `GET /api/stacks/some-team/some-repo/production/ccmenu?token=<leaked>`. Replay the same `token` with a different `stack_id` path segment, e.g. `GET /api/stacks/other-team/other-repo/production/ccmenu?token=<leaked>`. The token authenticates (`ApiClient.authenticate`), `require_permission :read, :stack` passes (permission list includes `read:stack`), and `stack` resolves to the victim stack unconditionally, returning that stack's `lastBuildStatus`, `lastBuildLabel`, `activity`, and `webUrl` in the `shipit/ccmenu/project` XML view: [6](#0-5) 

No existing guard (`verify_signature`, `force_github_authentication`, `require_permission!`, `EnvironmentVariables#permit`, model validators) prevents this divergence, since the CCMenu endpoint intentionally skips session-based authentication and the only per-request check (`read:stack` permission) is stack-agnostic.

### Impact Explanation
A single leaked CCMenu token grants unauthenticated read access to build/deploy status (`lastBuildStatus`, `activity`, `lastBuildLabel`, `webUrl`) for **every** stack in the Shipit instance, not just the one it was generated for — this is repeatable indefinitely against any stack_id an attacker can guess or enumerate. This matches the "High - unauthenticated read of stack state" category: any internet user holding one public CCMenu badge URL (e.g., pasted in a public README) can pivot to read deploy/build state of unrelated, potentially private repositories/teams they were never authorized to view.

### Likelihood Explanation
No privileged access is required beyond obtaining one legitimately-issued CCMenu token (a common, intentionally shareable artifact meant for public CI badges). The attacker only needs to change the `stack_id` path segment to a target stack's identifier (`owner/repo/environment`), which is often guessable or discoverable from public GitHub repo names. This is trivially reproducible with a single HTTP GET and requires no GitHub or Shipit secrets.

### Recommendation
Set `stack:` on the `ApiClient` created in `CCMenuUrlController#client` (scoping it per stack rather than per user), and restore stack-scoped resolution in `CCMenuController#stack` by using the shared `stacks.from_param!(params[:stack_id])` (or an explicit `current_api_client.stack_id == stack.id` check) instead of the unscoped `Stack.from_param!`.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a token minted for one stack cannot read another stack's build status" do
  victim_stack = Stack.create!(repository: Repository.new(owner: "victim", name: "repo"), branch: "main")
  origin_stack = shipit_stacks(:shipit)

  client = ApiClient.create!(creator: shipit_users(:walrus), name: 'CCMenu Client', permissions: %w[read:stack])
  # client.stack_id is nil -- never scoped to origin_stack

  get :show, params: { stack_id: victim_stack.to_param, token: client.authentication_token }

  assert_response :ok # should be :forbidden or :not_found if properly scoped
  assert_includes response.body, victim_stack.to_param # leaks victim deploy info
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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

**File:** app/views/shipit/ccmenu/project.xml.builder (L1-16)
```text
# frozen_string_literal: true

# Derived from http://timnew.me/blog/2013/04/07/multiple-project-summary-reporting-standard-cctray-xml-feed/
status_map = { 'backlogged' => 'failure', 'locked' => 'failure' }
xml.instruct!
xml.Projects do
  xml.Project(
    '',
    name: stack.to_param,
    lastBuildStatus: status_map.fetch(stack.merge_status, stack.merge_status).capitalize,
    activity: deploy.running? ? 'Building' : 'Sleeping',
    lastBuildTime: deploy.ended_at || deploy.started_at || deploy.created_at,
    lastBuildLabel: deploy.id,
    webUrl: stack_url(stack)
  )
end
```
