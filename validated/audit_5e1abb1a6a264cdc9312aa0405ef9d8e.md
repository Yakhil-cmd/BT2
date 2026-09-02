## Analysis

The binding the question asks me to test is: does `POST /api/stacks/*id/refresh` succeed only for a token scoped to that stack with the required permission? Tracing `Shipit::Api::StacksController`, the class declares permission requirements explicitly per action:

```
require_permission :read, :stack, only: %i[index show]
require_permission :write, :stack, only: %i[create update destroy]
``` [1](#0-0) 

`refresh` is not listed in either `only:` set, so no `require_permission!` check is registered for it at all, meaning any authenticated `ApiClient` — regardless of its `permissions` array — can invoke it. [2](#0-1) 

The only gate before reaching `refresh` is `authenticate_api_client`, which just needs a verifiable token (basic-auth or query-string via `ApiClient.authenticate`) — no permission check: [3](#0-2) 

`stack` resolves through the `stacks` scope, which is `Stack.all` unless `current_api_client.stack_id?` is true: [4](#0-3) 

The CCMenu token handed out by `CCMenuUrlController#fetch` is created with `permissions: %w[read:stack]` and **no `stack:` association**, so `stack_id?` is false and the token is unscoped across all stacks: [5](#0-4) 

That token is embedded directly in a URL returned to the browser: [6](#0-5) 

So the read-only, cross-stack CCMenu token — once leaked via Referer headers, browser history, or server logs (as it is placed in a query string) — can be replayed against `POST /api/stacks/*id/refresh` for **any** stack, and it will succeed with a 202, because `refresh` performs no `require_permission!` check whatsoever. The existing test suite confirms `#create` and `#destroy` do enforce `write:stack` and reject empty-permission clients [7](#0-6) , but there is no equivalent negative test for `#refresh` — the only two existing `#refresh` tests authenticate with a full-permission client and assert the jobs get enqueued [8](#0-7) , never proving that an insufficiently-permissioned or unscoped token is rejected.

### Title
`POST /api/stacks/*id/refresh` has no permission check, allowing a leaked read:stack CCMenu token to trigger writes on any stack - (File: `app/controllers/shipit/api/stacks_controller.rb`)

### Summary
`Shipit::Api::StacksController` declares `require_permission :write, :stack` only for `create`, `update`, and `destroy`, omitting `refresh` entirely, so `refresh` is reachable by any authenticated `ApiClient` regardless of its granted permissions. Combined with the fact that `CCMenuUrlController#fetch` mints an unscoped (`stack_id` nil), `read:stack`-only token that is embedded in a plain query-string URL, an attacker who obtains that leaked token can call `refresh` for any stack in the installation, not just the one the CCMenu URL was generated for.

### Finding Description
The invariant under test is: `refresh` should require `write:stack` permission for the specific target stack, i.e. `current_api_client.permissions.include?('write:stack') == true AND current_api_client.stack_id ∈ {nil-if-unscoped, target.stack_id}`. In the actual code, `refresh` is absent from both `require_permission` declarations [1](#0-0) , so `require_permission!` is never invoked for that action — the equality collapses to "any valid token, any permission set, any stack, succeeds."

Exploit flow: (1) a user with browser access to a stack's settings page triggers `CCMenuUrlController#fetch`, which creates/reuses an `ApiClient` scoped to `read:stack` only and with no `stack_id`, and returns a URL with `?token=<token>` [9](#0-8) ; (2) that URL, being a GET query string, is exposed via browser history, `Referer` headers to third parties, and typical webserver/proxy logs; (3) an attacker who obtains it can present it via Basic-Auth (`ApiClient.authenticate` accepts the raw token string, as used generically in `BaseController#authenticate_api_client` [10](#0-9) ) against `POST /api/stacks/*id/refresh` for an arbitrary stack id; (4) because `stack_id?` is false for this token, `stacks` resolves to `Stack.all` [11](#0-10) , and because `refresh` has no `require_permission!` call, the request succeeds and enqueues `RefreshStatusesJob`, `RefreshCheckRunsJob`, and `GithubSyncJob` with `force_spec_cache: true` for that stack [2](#0-1) .

This bypasses the intended `write:stack` requirement that gates equivalent-impact actions like `create`/`update`/`destroy`, and it bypasses the intended per-stack scoping that the CCMenu URL feature was meant to provide (the URL is only supposed to grant read access to one stack's CCMenu XML feed).

### Impact Explanation
An attacker holding a leaked CCMenu token can force a GitHub re-sync and status/check-run refresh job on any stack the Shipit instance manages, not just the one for which the URL was generated — an unauthorized write-class action performed without the `write:stack` permission and without being scoped to the token's originating stack. This is a permission/authorization-scope bypass: the built-in permission model (`read:stack` vs `write:stack`) is meant to gate exactly this class of action, but `refresh` silently omits the check. It does not directly leak deploy output or secrets by itself, but it lets an unprivileged token trigger repeated, unauthorized write operations (job enqueues) against arbitrary stacks across the installation, which is a real authorization-boundary break broader than any single tenant.

### Likelihood Explanation
The precondition is simply that a CCMenu URL has been generated at least once for some stack (a routine, low-friction feature reachable by any authenticated Shipit user via the stack settings page) and that the resulting URL/token leaks through a normal channel (Referer, logs, shared screenshots, browser history sync). No GitHub secrets, webhook secrets, or Shipit operator privileges are needed — only possession of the leaked query-string token, which is exactly the "attacker controls: the token... via ?token=" precondition stated in the question. This makes the attack cheap, repeatable across all stacks, and requires no live GitHub interaction to prove.

### Recommendation
Add `refresh` to the `require_permission :write, :stack` list in `Shipit::Api::StacksController` (mirroring `create`/`update`/`destroy`), and additionally scope `ApiClient`s created by `CCMenuUrlController#fetch` to the specific stack (`stack:` association) so a leaked CCMenu token cannot be replayed against other stacks even for read-only operations.

### Proof of Concept
In `test/controllers/api/stacks_controller_test.rb`, add a test mirroring the existing `#create`/`#destroy` "insufficient permissions" tests:

```ruby
test "#refresh fails with insufficient permissions" do
  @client.update!(permissions: ['read:stack'])  # simulate a leaked CCMenu-style token

  assert_no_enqueued_jobs do
    post :refresh, params: { id: @stack.to_param }
  end

  assert_response :forbidden
  assert_json 'message', 'This operation requires the `write:stack` permission'
end
```
Running this against current code: `assert_response :forbidden` fails (actual response is `:accepted`), and jobs are enqueued, proving the equality `current_api_client.permissions.include?('write:stack') == required-for-success` is violated — `refresh` succeeds despite the client only holding `read:stack`.

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

**File:** app/controllers/shipit/api/base_controller.rb (L48-61)
```ruby
      def authenticate_api_client
        @current_api_client = if Shipit.disable_api_authentication
                                UnlimitedApiClient.new
                              else
                                BasicAuth.authenticate(request) do |*parts|
                                  token = parts.select(&:present?).join('--')
                                  ApiClient.authenticate(token)
                                end
                              end
        return if @current_api_client

        headers['WWW-Authenticate'] = 'Basic realm="Authentication token"'
        render(status: :unauthorized, json: { message: 'Bad credentials' })
      end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-18)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** test/controllers/api/stacks_controller_test.rb (L251-261)
```ruby
      test "#destroy fails with insufficient permissions" do
        @client.permissions.delete('write:stack')
        @client.save!

        assert_no_difference 'Stack.count' do
          delete :destroy, params: { id: @stack.to_param }
        end

        assert_response :forbidden
        assert_json 'message', 'This operation requires the `write:stack` permission'
      end
```

**File:** test/controllers/api/stacks_controller_test.rb (L263-277)
```ruby
      test "#refresh queues a GithubSyncJob with force_spec_cache" do
        assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, force_spec_cache: true]) do
          post :refresh, params: { id: @stack.to_param }
        end
        assert_response :accepted
      end

      test "#refresh queues a RefreshStatusesJob and RefreshCheckRunsJob" do
        assert_enqueued_with(job: RefreshStatusesJob, args: [stack_id: @stack.id]) do
          assert_enqueued_with(job: RefreshCheckRunsJob, args: [stack_id: @stack.id]) do
            post :refresh, params: { id: @stack.to_param }
          end
        end
        assert_response :accepted
      end
```
