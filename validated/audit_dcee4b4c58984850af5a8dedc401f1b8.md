There's no test exercising a stack-scoped `here_come_the_walrus` client against `Api::CCMenuController` with a *different* `stack_id` — every test in `test/controllers/api/ccmenu_controller_test.rb` uses the default `:spy` client (unscoped, `stack_id` column nil), so the scoping bypass is untested and unnoticed. This confirms the finding.

### Title
Stack-scoped API token bypasses its stack authorization in `Api::CCMenuController#show` - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::CCMenuController` overrides the `stack` lookup helper to resolve `params[:stack_id]` against the entire `Stack` table instead of the caller's authorized stack scope, letting an `ApiClient` token that is restricted to a single stack read the CI status of any other stack in the installation.

### Finding Description
Shipit's API authorization model binds an `ApiClient` token to a specific stack via the `stack_id` column: `Api::BaseController#stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the client is scoped, and the generic `Api::BaseController#stack` helper resolves the requested resource through that restricted relation: `@stack ||= stacks.from_param!(params[:stack_id])`. [1](#0-0) 

`Api::CCMenuController` (mounted at `/api/stacks/*stack_id/ccmenu`) instead defines its own private `stack` method that ignores this scoping entirely and resolves any stack by id directly: [2](#0-1) 

The controller only enforces `require_permission :read, :stack`, which calls `ApiClient#check_permissions!` — a check that verifies the token *has* the `read:stack` permission bit, but never verifies *which* stack the token is scoped to: [3](#0-2) 

This breaks the binding "a stack a token authorises versus a stack it touches": the token authorizes reads for `current_api_client.stack_id`, but the controller lets it touch an arbitrary `stack_id` supplied in the request path. Every other resource-scoped API controller (e.g. `Api::StacksController#stack`, `Api::TasksController`, `Api::HooksController`) reuses the inherited scoped `stack`/`stacks` helper and is not affected; `CCMenuController` is the outlier that redefines it with an unscoped lookup.

### Impact Explanation
An attacker holding any stack-scoped API token with `read:stack` permission (e.g. distributed to CI dashboards via `CCMenuUrlController`, which itself mints a `read:stack`-scoped `ApiClient` and embeds its token in a shareable URL) can query `/api/stacks/<any-other-owner>/<repo>/<env>/ccmenu` and receive that other stack's deploy/build status — including `lastBuildStatus`, `lastBuildLabel` (deploy id), `lastBuildTime`, `webUrl`, and lock state — for stacks the token was never authorized to see. This is an authenticated-but-unauthorized cross-stack read of stack/deploy state, matching the "unauthenticated read of stack state, task streams or deploy output" class of High-severity impact, since the token's authorization is effectively meaningless for this endpoint.

### Likelihood Explanation
The bypass requires only possession of any valid, stack-scoped API token with the `read:stack` permission and no other privileges — the endpoint is unauthenticated with respect to which stack it serves and needs no admin/organization trust. Such tokens are explicitly designed to be shared narrowly (e.g., embedded in CI dashboard URLs by `CCMenuUrlController`), making exploitation straightforward for anyone who obtains one such token, regardless of the specific stack it was minted for.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the inherited scoped lookup (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so a stack-scoped token can only resolve the single stack it is authorized for, consistent with `Api::BaseController#stack`.

### Proof of Concept
1. As an admin, mint (or let `CCMenuUrlController#fetch` mint) an `ApiClient` scoped to `stack: shipit_stacks(:shipit)` with `permissions: ['read:stack']` (mirrors fixture `here_come_the_walrus` in `test/fixtures/shipit/api_clients.yml`).
2. Using that token's `authentication_token` for Basic Auth, request `GET /api/stacks/<some-other-owner>/<some-other-repo>/<env>/ccmenu` where `<some-other-owner>/<some-other-repo>/<env>` is a stack outside the token's `stack_id`.
3. Because `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` (see `app/controllers/shipit/api/ccmenu_controller.rb:29-31`) rather than the scoped `stacks.from_param!`, the request returns `200 OK` with that other stack's CCMenu XML (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, etc.), even though the token's `stack_id` restricts it to a different stack — compare with `Api::StacksController#show`, which correctly 404s for out-of-scope stacks via `stacks.from_param!` (`app/controllers/shipit/api/stacks_controller.rb:87-89`).

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
