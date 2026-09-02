### Title
Unscoped `read:stack` API token minted by CCMenu URL, granting installation-wide stack read access - (File: app/controllers/shipit/ccmenu_url_controller.rb)

### Summary
`Shipit::CCMenuUrlController#client` creates an `ApiClient` with `read:stack` permission but never binds it to the requested stack (`stack: stack` is omitted from `create_with`/`find_or_create_by!`), leaving `ApiClient#stack_id` `nil`. Combined with `Api::BaseController#stacks` falling back to `Stack.all` whenever `current_api_client.stack_id?` is false, the CCMenu token minted for one stack can read every stack in the installation via the API.

### Finding Description
The claimed binding is: `client.stack_id == stack.id` for the stack requested in `GET /ccmenu/*stack_id/`. Tracing the code shows this never holds.

- `#stack` resolves the target with no ownership/authorization check: `Stack.from_param!(params[:stack_id])` [1](#0-0) .
- `#client` mints (or reuses) an `ApiClient` scoped only by `creator` and `name`, never by `stack`: `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` [2](#0-1) .
- `ApiClient` has `belongs_to :stack, optional: true` [3](#0-2) , so an unscoped create leaves `stack_id` as `nil`.
- On the API side, authorization narrowing depends entirely on that field: `@stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [4](#0-3) . Since `stack_id` is `nil`, `stack_id?` is false and the token is granted `Stack.all`.

Because `find_or_create_by!` keys only on `creator` + `name`, this also means a single user's "CCMenu Client" record is reused across every stack they ever request a CCMenu URL for — the token is never per-stack, by construction, not merely due to a missing check elsewhere. `ShipitController` (the base class for `CCMenuUrlController`) has no per-stack authorization filter of its own — it only runs `ensure_required_settings` and includes `Shipit::Authentication` for identifying `current_user` [5](#0-4) ; access control for API scoping is expected to be enforced via `ApiClient#stack_id`, which this endpoint fails to set.

Attacker flow: an authenticated Shipit user calls `GET /ccmenu/<owner>/<repo>/<stack>/` for any stack path they can guess or enumerate (`stack_id_format` is just three URL segments, routed at `scope '/ccmenu/*stack_id'`, `as: :ccmenu_url` [6](#0-5) ). The response embeds `client.authentication_token`, a Basic-Auth-usable token with `read:stack` and no `stack_id`, i.e. valid against every stack via `Api::StacksController#index`/`#show` and other `read:stack`-gated endpoints.

### Impact Explanation
The minted token, though obtained via a single-stack CCMenu request, decodes at the API layer to `Stack.all`, so the calling user can read status/task/commit data for every stack in the installation, not just the one they requested — a cross-tenant unauthorized read of stack state. It does not grant write/deploy permissions (`permissions: %w[read:stack]` only), so it does not enable mutation or RCE, but it does break the intended per-repository isolation of stack visibility. This matches the "unauthenticated/unauthorized read of stack state" High-severity category, is repeatable per user (each user only needs to mint their own "CCMenu Client" once), and its blast radius spans all stacks/tenants hosted by the Shipit instance.

### Likelihood Explanation
No special privilege is required beyond a valid Shipit session (any logged-in user, including one who only maintains their own unrelated repository), and no GitHub team membership or maintainer role on the target stack is checked before `#stack` or `#client` run. The attacker only needs to know or guess a `stack_id` path (`owner/repo/branch`), which is often discoverable via the stacks list UI. Cost is a single HTTP GET; the resulting token is durable (stored `ApiClient` record) and reusable across the whole installation until revoked.

### Recommendation
Bind the minted client to the specific stack, e.g. `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, stack: stack, name: 'CCMenu Client')`, and add a uniqueness/lookup key on `(creator, stack, name)` instead of `(creator, name)` alone. Additionally, add an authorization check in `#stack` (e.g., verify `current_user` is permitted to view `stack`'s repository) before minting any token.

### Proof of Concept
Minitest plan under `test/controllers/ccmenu_url_controller_test.rb`:
1. Create `stack_a` (repository X) and `stack_b` (repository Y), and a logged-in `user` who is not a maintainer of Y.
2. `get :fetch, params: { stack_id: stack_a.to_param }` as `user`; parse the JSON, extract `token` query param from `ccmenu_url`.
3. Load the created `ApiClient` for `user` and assert `client.stack_id.nil?` (fails the intended binding `client.stack_id == stack_a.id`).
4. Using `Api::StacksController#index` with HTTP Basic auth via the extracted token, assert the returned stacks collection includes `stack_b` (and any other stack), proving the token is not scoped to `stack_a`.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L20-22)
```ruby
    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
```

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```

**File:** app/controllers/shipit/shipit_controller.rb (L16-18)
```ruby
    before_action :ensure_required_settings

    include Shipit::Authentication
```

**File:** config/routes.rb (L49-51)
```ruby
  scope '/ccmenu/*stack_id', stack_id: stack_id_format, as: :ccmenu_url do
    get '/' => 'ccmenu_url#fetch'
  end
```
