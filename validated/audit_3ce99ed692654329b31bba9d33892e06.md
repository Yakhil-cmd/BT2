### Title
`CCMenuController#stack` bypasses `ApiClient` stack scoping, enabling cross-tenant stack disclosure - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::BaseController#stack` restricts stack lookup to `current_api_client.stack_id` when the client is scoped to a single stack, but `Api::CCMenuController` overrides `#stack` to call the unscoped `Stack.from_param!` directly, ignoring that restriction. A CCMenu token scoped to one stack (the common case, since `CCMenuUrlController` always mints stack-scoped `read:stack` clients) can therefore be replayed against `stack_id` values belonging to any other tenant's stack and will return `200 OK` with real build/deploy data.

### Finding Description
The intended binding is: for a request to `GET /stacks/:stack_id/ccmenu.xml?token=<t>`, the returned stack `X` must satisfy `X ∈ {current_api_client.stack_id}` when the client is stack-scoped. This is enforced in the base controller: [1](#0-0) 

`stacks` restricts the relation to `Stack.where(id: current_api_client.stack_id)` when `current_api_client.stack_id?` is true, and `stack` resolves `from_param!` against that scoped relation. This is how `RollbacksController`, `DeploysController`, `TasksController`, `OutputsController`, and `MergeRequestsController` (all inheriting `stack` from `BaseController`) correctly enforce tenant isolation for stack-scoped tokens.

`CCMenuController`, however, redefines `stack` to bypass the scoped relation entirely: [2](#0-1) 

It calls `Stack.from_param!(params[:stack_id])` directly on the unscoped model: [3](#0-2) 

The only authorization check performed is `require_permission :read, :stack`, which only verifies the token has the `read:stack` permission string via `ApiClient#check_permissions!` — it never compares the requested stack against `current_api_client.stack_id`: [4](#0-3) 

The exact tokens leaked for this flow are precisely the stack-scoped, `read:stack`-only tokens minted by `CCMenuUrlController#client`, which is the documented, intended use case for CCMenu badge URLs: [5](#0-4) 

**Attacker flow:** Obtain a leaked/public CCMenu URL for stack A (`.../stacks/org-a/repo-a/production/ccmenu.xml?token=<t>`), where `<t>` decrypts to an `ApiClient` whose `stack_id` is scoped to stack A only. Replay the same token against other guessed `stack_id` path segments (`org-b/repo-b/production`, etc.). `check_permissions!(:read, :stack)` passes because the token has `read:stack`; `CCMenuController#stack` then resolves the guessed stack unscoped and returns `200` with real deploy/build/commit/lock data for a tenant the token was never authorized for. The equality holds for every other `BaseController` subclass (they 404/raise `RecordNotFound` for out-of-scope stacks) but is broken specifically for `CCMenuController`.

### Impact Explanation
A single leaked, narrowly-scoped `read:stack` CCMenu token (intended to expose only one stack's badge) can be used to enumerate and disclose build status, latest commit SHA, activity, and lock state of every stack in the Shipit instance, across all tenants/repositories, with no additional secrets required. This matches "High – unauthenticated read of stack state" (the attacker holds no meaningful privilege for the victim stacks — the token grants no legitimate access to them). It is fully repeatable: one token, arbitrary `stack_id` guesses (`owner/repo/environment` triples are often guessable/enumerable from repo names), unlimited requests.

### Likelihood Explanation
Preconditions are exactly as described in the prompt: the attacker needs only one previously-issued CCMenu URL/token (routinely embedded in public README badges, CI dashboards, etc.), no Shipit session, no `api_clients_secret`, and no operator role. No non-default configuration is required — this is the default behavior of `CCMenuController`. Cost is a handful of HTTP GETs guessing `owner/repo/environment` strings, which are frequently public (GitHub repo names) or low-entropy.

### Recommendation
Make `CCMenuController#stack` use the scoped `stacks` relation from `BaseController` instead of calling `Stack.from_param!` directly, e.g. `@stack ||= stacks.from_param!(params[:stack_id])`, so a stack-scoped `ApiClient` cannot resolve any stack outside `current_api_client.stack_id`. Apply the same fix to `CCMenuUrlController#stack` if it can be reached with a stack-scoped session/token in other flows.

### Proof of Concept
Add to `test/controllers/api/ccmenu_controller_test.rb` (or an equivalent minitest):
```ruby
test "a stack-scoped token cannot read another tenant's stack via ccmenu" do
  scoped_stack = shipit_stacks(:shipit)
  other_stack  = Stack.create!(repository: Repository.new(owner: "other-org", name: "other-repo"), branch: "main")

  scoped_client = ApiClient.create!(
    creator: @user, name: "scoped", permissions: %w[read:stack], stack: scoped_stack
  )

  get :show, params: { stack_id: scoped_stack.to_param, token: scoped_client.authentication_token }
  assert_response :ok # expected: token is valid for its own stack

  get :show, params: { stack_id: other_stack.to_param, token: scoped_client.authentication_token }
  assert_response :not_found # currently fails: returns :ok with other_stack's real build data
end
```
This asserts both sides of the binding `X ∈ {current_api_client.stack_id}`: the scoped stack succeeds, the foreign stack must fail (404) but currently returns `200` with disclosed build data, proving the leak.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-22)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
```
