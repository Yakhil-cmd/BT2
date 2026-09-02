### Title
`Api::StacksController#refresh` performs a stack-scoped mutation with no `require_permission` guard, letting a `read:stack` token trigger arbitrary-stack sync jobs - (File: `app/controllers/shipit/api/stacks_controller.rb`)

### Summary
`StacksController` declares `require_permission :read, :stack, only: %i[index show]` and `require_permission :write, :stack, only: %i[create update destroy]`, but the `refresh` action is not listed in either `only:` array, so no `before_action` calls `require_permission!` for it. `refresh` enqueues `RefreshStatusesJob`, `RefreshCheckRunsJob`, and `GithubSyncJob` for the target stack, which is a mutating side effect equivalent in scope to `write:stack`, yet it is reachable by any authenticated `ApiClient` regardless of its `permissions` array.

### Finding Description
The binding the codebase intends is: *the permission declared for an action == the permission its side effect requires*. For `refresh` this is broken: declared permission = `none` (no `require_permission` before_action matches `only: [:refresh]`), while the actual side effect is enqueuing three background jobs that mutate stack-scoped state (`app/controllers/shipit/api/stacks_controller.rb:69-79`):

```ruby
def refresh
  RefreshStatusesJob.perform_later(stack_id: stack.id)
  RefreshCheckRunsJob.perform_later(stack_id: stack.id)
  GithubSyncJob.perform_later(stack_id: stack.id, force_spec_cache: true)
  render_resource(stack, status: :accepted)
end
``` [1](#0-0) [2](#0-1) 

`Api::BaseController.require_permission` only installs a scoped `before_action` when `options` (e.g. `only:`) is supplied (`app/controllers/shipit/api/base_controller.rb:18-22`); actions absent from every `only:` list on a controller run with zero permission checks beyond `authenticate_api_client`. `authenticate_api_client` only proves the token is valid (`app/controllers/shipit/api/base_controller.rb:48-61`), it performs no scope/permission check itself.

Exploit flow: an attacker who can reach `CCMenuUrlController#fetch` (any Shipit user with view access to a stack settings page, or anyone who obtains the badge URL) causes `CCMenuUrlController#client` to mint/reuse an `ApiClient` with `permissions: %w[read:stack]` and no `stack_id` scoping (`app/controllers/shipit/ccmenu_url_controller.rb:15-18`), so `stacks` in `BaseController` resolves to `Stack.all` for that token (`app/controllers/shipit/api/base_controller.rb:74-76`). The attacker then sends `POST /api/stacks/:id/refresh` (route defined in `config/routes.rb:24`) with the `Authorization` basic-auth header set to that token, for any `:id` (any repo_owner/repo_name/environment), and the jobs are enqueued for that arbitrary stack with no permission check at all.

Existing guards do not catch this: `authenticate_api_client` only validates the token's HMAC signature, not its permission set; `require_permission!`/`check_permissions!` are never invoked for this action because the `before_action(options) { ... }` from `require_permission :write, :stack, only: %i[create update destroy]` explicitly excludes `refresh`. The controller test suite confirms the gap: `create` and `destroy` each have a "`fails with insufficient permissions`" test, but no such test exists for `refresh` (`test/controllers/api/stacks_controller_test.rb:263-277`).

### Impact Explanation
Any holder of a minimally-permissioned (or even future zero-permission) `ApiClient` token can force-enqueue `GithubSyncJob` (which recomputes and force-writes the cached deploy spec), `RefreshStatusesJob`, and `RefreshCheckRunsJob` for any stack in the installation, not just the stack the token was minted for. Because the CCMenu-issued token is unscoped (`stack_id` nil), this reaches every stack across every repository/tenant hosted by the Shipit instance - satisfying the "payload for one repository mutating another's stack" category. Repeatable per request, with no rate limiting on the endpoint itself.

### Likelihood Explanation
Low attacker cost: obtaining a `read:stack`-only token only requires being able to load a stack's settings page (or the public-facing CCMenu badge URL) to trigger `CCMenuUrlController#fetch`, which mints/returns the token in cleartext in the JSON response. No secrets, no privileged role, no GitHub App key required. The only precondition is that the target Shipit instance exposes the CCMenu URL fetch flow (default engine behavior) and does not otherwise restrict `/api/stacks/*/refresh`.

### Recommendation
Add `refresh` to a `require_permission` declaration matching its actual side effect, e.g.:
```ruby
require_permission :write, :stack, only: %i[create update destroy refresh]
```
More generally, audit every `Api::*Controller` for actions omitted from all `require_permission only:` lists and either cover them explicitly or default `require_permission` to apply engine-wide (no `only:`) unless overridden per-action.

### Proof of Concept
In `test/controllers/api/stacks_controller_test.rb`, add:
```ruby
test "#refresh fails with insufficient permissions" do
  @client.update!(permissions: ['read:stack'])
  assert_no_enqueued_jobs do
    post :refresh, params: { id: @stack.to_param }
  end
  assert_response :forbidden
  assert_json 'message', 'This operation requires the `write:stack` permission'
end
```
Running this against current code: the assertion `assert_no_enqueued_jobs` fails (three jobs are enqueued) and `assert_response :forbidden` fails (response is `:accepted`), proving `refresh` is reachable with only `read:stack` permission — confirming the declared-permission (`none`) vs required-permission (`write:stack`) binding is broken for this action.

### Citations

**File:** app/controllers/shipit/api/stacks_controller.rb (L6-7)
```ruby
      require_permission :read, :stack, only: %i[index show]
      require_permission :write, :stack, only: %i[create update destroy]
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L69-79)
```ruby
      def refresh
        RefreshStatusesJob.perform_later(stack_id: stack.id)
        RefreshCheckRunsJob.perform_later(stack_id: stack.id)
        # force_spec_cache: explicit refreshes always recompute the cached deploy
        # spec, even when the head hasn't moved: refreshing is how a stale or
        # broken cached spec is fixed. Threading it through the sync job (rather
        # than enqueuing CacheDeploySpecJob directly) guarantees the spec is
        # computed from the post-sync head.
        GithubSyncJob.perform_later(stack_id: stack.id, force_spec_cache: true)
        render_resource(stack, status: :accepted)
      end
```
