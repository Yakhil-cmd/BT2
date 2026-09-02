### Title
Unscoped CCMenu API token grants `read:stack` access to every stack in the instance - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`CCMenuUrlController#client` mints an `ApiClient` token intended to expose a single stack's CI status via the public CCMenu XML feed, but the created record never sets `stack:`, so the token is unscoped and authorizes `read:stack` against every stack managed by the Shipit instance rather than only the stack for which the URL was generated.

### Finding Description
`CCMenuUrlController#fetch` builds a public, unauthenticated-looking URL containing an API token for one specific stack: [1](#0-0) 

The token is produced by:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
```
Notice that `stack:` is never passed to `create_with`/`find_or_create_by!`, so the resulting `ApiClient` row has `stack_id = nil`.

Authorization for API requests is resolved in `Api::BaseController`: [2](#0-1) 
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end
```
Because `stack_id?` is false for the CCMenu client, `stacks` resolves to `Stack.all` for any request authenticated with this token, and `Api::StacksController#show`/`#index` only require the `read:stack` permission scope, not a matching stack: [3](#0-2) 

This breaks the intended binding: *the stack the token is meant to authorize* (the one embedded in the generated CCMenu URL) *≠ the stack(s) the token actually touches* (all stacks in the instance). Any consumer of the CCMenu URL - which is designed to be embedded in build-monitor tools and is often placed on semi-public dashboards - obtains a durable bearer credential (`ApiClient#authentication_token`, an `ActiveSupport::MessageVerifier`-signed id) that can be replayed against `GET /api/stacks`, `GET /api/stacks/:id`, and any other `read:stack`-scoped endpoint for every stack in the deployment, not just the one it was generated for.

### Impact Explanation
This matches the "stack a token authorises versus a stack it touches" trust-binding category. Anyone holding this single-stack CCMenu token (e.g., leaked from a status-board embed, browser history, proxy logs, or shared dashboard) can enumerate and read the state of every stack in the Shipit instance (`Api::StacksController#index`/`#show`), which qualifies as an unauthenticated read of stack state — a High-impact finding per the given rubric.

### Likelihood Explanation
Likelihood is high in practice: CCMenu URLs are explicitly designed to be embedded in third-party build-status tools and dashboards (often outside Shipit's authentication boundary), so token exposure is an expected and common occurrence, and no additional privilege beyond obtaining the URL is required to pivot to reading all other stacks.

### Recommendation
Scope the CCMenu API client to the specific stack when creating it, e.g.:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack], stack: stack)
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client', stack: stack)
end
```
and ensure the `find_or_create_by!` lookup includes `stack:` so that a client already created for one stack can't be silently reused/widened for another, and that existing unscoped `CCMenu Client` records are backfilled or revoked.

### Proof of Concept
1. As an authenticated Shipit user, visit `GET /ccmenu/<owner>/<repo>/<environment>` for `stack A`. Shipit creates (or reuses) an `ApiClient` named "CCMenu Client" with `permissions: [read:stack]` and `stack_id: nil`, and returns a URL like `https://.../api/stacks/<A-id>/ccmenu.xml?token=<token>`.
2. Extract `<token>` from the URL.
3. Issue `curl -u <token>: https://<host>/api/stacks` or `https://<host>/api/stacks/<B-id>` where `B` is an unrelated stack the requester should not have access to.
4. Because `ApiClient#stack_id` is `nil`, `Api::BaseController#stacks` resolves to `Stack.all`, `require_permission :read, :stack` passes (the client has `read:stack`), and the response returns stack `B`'s data, proving the token exceeds its intended per-stack scope.

*(Note: I was unable to execute this PoC against a running instance within the scope of this analysis; the conclusion is based on static code review of `ccmenu_url_controller.rb`, `api_client.rb`, and `api/base_controller.rb`.)*

### Citations

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

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L6-24)
```ruby
      require_permission :read, :stack, only: %i[index show]
      require_permission :write, :stack, only: %i[create update destroy]

      params do
        accepts :repo_owner, String
        accepts :repo_name, String
      end
      def index
        @stacks = stacks
        if params[:repo_owner] && params[:repo_name]
          full_repo_name = [repo_owner, repo_name].join('/')
          @stacks = if (repository = Repository.from_github_repo_name(full_repo_name))
                      stacks.where(repository:)
                    else
                      Stack.none
                    end
        end
        render_resources(@stacks)
      end
```
