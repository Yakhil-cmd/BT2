I have enough evidence to write up the finding now.

### Title
CCMenuController#stack bypasses ApiClient stack scoping, letting a stack-scoped token read the build status of any stack - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` scopes every resource lookup to the stacks an `ApiClient` is authorised for via `stacks`/`stack`, but `Shipit::Api::CCMenuController` overrides `#stack` to resolve directly against `Stack.from_param!(params[:stack_id])`, skipping that scoping. A token created with `stack_id` set (i.e. authorised for a single stack) can therefore query the CCMenu endpoint for any other stack by simply changing the `stack_id` request parameter, reading that stack's build status, activity, last build label, and web URL — a stack the token was never authorised to touch.

### Finding Description
`Shipit::Api::BaseController` defines the authorization-scoped resource resolvers: [1](#0-0) 

`stacks` restricts the visible set to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` has a `stack_id` set, which is exactly how per-stack scoped tokens are meant to be constrained (see the `here_come_the_walrus` fixture, which is `stack: shipit` scoped, and the passing test "an api client scoped to a stack will only see that one stack").

`require_permission` only checks category-level permission strings like `read:stack` on the `ApiClient` model — it never checks which specific stack is being accessed: [2](#0-1) 

The per-request restriction to the token's authorised stack is therefore entirely delegated to `BaseController#stack` / `#stacks`. `CCMenuController`, however, overrides `#stack` to bypass that scoped collection and resolve against the entire `Stack` table: [3](#0-2) 

`Stack.from_param!` performs a lookup by owner/name/environment with no `ApiClient` scoping at all: [4](#0-3) 

This exactly matches the analog bound: **stack a token authorises ≠ stack it touches**. `require_permission :read, :stack` verifies the *permission category* is present on the token, then `#show` calls `stack.deploys_and_rollbacks.last`, rendering `lastBuildStatus`, `activity`, `lastBuildLabel`, `lastBuildTime`, and `webUrl` for whichever stack the `stack_id` parameter names: [5](#0-4) [6](#0-5) 

### Impact Explanation
An `ApiClient` token that was intentionally scoped to a single stack (`stack_id` set, e.g. to hand a CI/monitoring integration read access to exactly one stack's CCTray feed) can be replayed against `Api::CCMenuController#show` with a different `stack_id` to read the build/lock/lastBuildLabel/activity state of any other stack in the Shipit instance, including stacks belonging to unrelated repositories the token owner was never granted access to. This is an unauthorized read of stack state via a token whose authorization boundary is a single stack — matching the High-impact criterion "unauthenticated read of stack state ... " in a cross-stack sense (a token authorized for stack A reads stack B).

### Likelihood Explanation
Exploitation requires only possession of any valid `read:stack`-permitted `ApiClient` token (even one deliberately scoped to a single, low-sensitivity stack) and knowledge/guessing of another stack's `owner/name/environment` identifier — no additional privilege, signature, or session is needed, and the mechanism (just changing a URL parameter) is trivial to exploit once a token is held.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the scoped `stacks` collection inherited from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so that stack-scoped tokens cannot read state for stacks outside their authorised scope.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_id: <Stack A>.id` with `permissions: ['read:stack']` (as done for the `here_come_the_walrus` fixture).
2. Authenticate as that client and request:
   `GET /api/ccmenu/<Stack B owner>/<Stack B name>/<Stack B environment>?token=<token>`
   where Stack B is a different stack the client was not scoped to.
3. `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly (bypassing `BaseController#stacks`'s `current_api_client.stack_id` restriction), so the request succeeds with `200 OK` and returns Stack B's `lastBuildStatus`, `activity`, `lastBuildLabel`, and `webUrl` — data the token was never authorised to see, as confirmed by contrasting with `BaseController#stack`/`#stacks` at [1](#0-0)  and the fixture-driven scoping test in `test/controllers/api/stacks_controller_test.rb` (`"an api client scoped to a stack will only see that one stack"`) which relies on that same `stacks` method that `CCMenuController` skips.

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

**File:** app/models/shipit/stack.rb (L515-525)
```ruby
    def self.from_param!(param)
      repo_owner, repo_name, environment = param.split('/')
      includes(:repository)
        .where(
          repositories: {
            owner: repo_owner.downcase,
            name: repo_name.downcase
          },
          environment:
        ).first!
    end
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
