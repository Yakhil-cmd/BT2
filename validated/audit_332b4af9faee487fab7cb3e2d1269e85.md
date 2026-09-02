### Title
CCMenu build-status token is not scoped to its intended stack, granting instance-wide `read:stack` API access - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
The `CCMenuUrlController#fetch` action mints an `ApiClient` token meant to expose only the CCMenu/CCTray build-status feed of a single stack. The token is created without binding it to that stack (`stack_id` is left `nil`), so the "one stack" scope shown in the generated URL is never enforced at the authentication layer. Because `Api::BaseController` treats a token with `stack_id == nil` as authorized for **every** stack, the same token can be replayed with Basic Auth against any endpoint gated only by the `read:stack` permission (`Api::StacksController#index/#show`, `Api::TasksController#index/#show`), exposing every stack's configuration and task/deploy history in the Shipit instance.

### Finding Description
`CCMenuUrlController#client` creates the token like this: [1](#0-0) 

Note that only `permissions: %w[read:stack]` is set — `stack:` (the `belongs_to :stack, optional: true` association on `ApiClient`) is never assigned, so the persisted token has `stack_id == nil`.

`Api::BaseController` resolves which stacks a token is allowed to see purely from that `stack_id`: [2](#0-1) 

When `stack_id` is `nil`, `stacks` degrades to `Stack.all`, i.e., the token becomes an unscoped, instance-wide credential rather than the single-stack credential implied by the CCMenu URL it was minted for (`.../api/stacks/<that_stack>/ccmenu?token=...`).

This same `ApiClient` record authenticates through the generic `authenticate_api_client` filter shared by every API controller: [3](#0-2) 

Any controller that only requires `read:stack` accepts this token, e.g.: [4](#0-3) [5](#0-4) 

The broken binding is: `token.stack_id == the single stack the ccmenu_url was generated for`. In reality `token.stack_id` is always `nil`, so the equality never holds — the token "authorises" (per intent) exactly one stack but "touches" (per code) all stacks.

### Impact Explanation
This matches the High-impact category "unauthenticated read of stack state, task streams or deploy output": CCMenu/CCTray links are designed to be shared broadly (embedded in office dashboards, monitoring tools, status widgets) and are not treated as sensitive Shipit credentials by design/documentation. Anyone who obtains one such link can use its embedded `token` as a full `read:stack` Basic-Auth credential to enumerate every stack in the installation (`GET /api/stacks`), read full configuration/status of any stack (`GET /api/stacks/:id`), and read the task/deploy history of any stack (`GET /api/stacks/:id/tasks`) — none of which is limited to the stack the link was created for.

### Likelihood Explanation
Every stack page that offers a CCMenu URL triggers this code path (`CCMenuUrlController#fetch`), so the mis-scoped token is created by default whenever the feature is used — no misconfiguration is required. Exploitation only requires possession of a previously-shared CCMenu URL, which is exactly what the feature is meant to be shared for.

### Recommendation
Bind the token to the stack it is generated for and enforce that scope everywhere it is used:
- In `CCMenuUrlController#client`, pass `stack:` when creating/finding the `ApiClient` (e.g. `find_or_create_by!(creator: current_user, stack:, name: 'CCMenu Client')`), and include `stack_id` in the `find_or_create_by!` lookup keys so a distinct client is created per stack.
- Remove the `stack` override in `Api::CCMenuController` that bypasses the base `stacks` scoping (`app/controllers/shipit/api/ccmenu_controller.rb:29-31`), and rely on `Api::BaseController#stack`/`#stacks` so scoping is consistently enforced.
- Consider making `Api::BaseController#stacks` fail closed rather than defaulting to `Stack.all` when `stack_id` is blank, for tokens whose intended use is single-stack.

### Proof of Concept
1. A Shipit user opens Stack A's page; the UI calls `GET /stacks/A/ccmenu_url`, which returns `{"ccmenu_url": "https://shipit.example.com/api/stacks/A/ccmenu?token=T"}` where `T` is the `ApiClient` token created with `permissions: ["read:stack"]` and `stack_id: nil`.
2. That URL is embedded in a public build-status dashboard/widget (the normal use case for CCMenu/CCTray feeds) and becomes known to a third party who has no Shipit account.
3. The third party extracts `T` and calls:
   - `curl -u "T:" https://shipit.example.com/api/stacks` → returns JSON for **every** stack in the instance, not just A.
   - `curl -u "T:" https://shipit.example.com/api/stacks/B` → returns full details of an unrelated, possibly private stack B.
   - `curl -u "T:" https://shipit.example.com/api/stacks/B/tasks` → returns the deploy/task history of stack B.
4. All three calls succeed because `ApiClient#stack_id` is `nil`, so `Api::BaseController#stacks` resolves to `Stack.all` for token `T`, even though the token was only ever meant to expose stack A's build badge.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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

**File:** app/controllers/shipit/api/tasks_controller.rb (L6-11)
```ruby
      require_permission :read, :stack
      require_permission :deploy, :stack, only: %i[trigger abort]

      def index
        render_resources(stack.tasks)
      end
```
