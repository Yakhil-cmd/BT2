### Title
CCMenu Client token is shared across all stacks a user can view and grants stack-unscoped `read:stack` access - (File: app/controllers/shipit/ccmenu_url_controller.rb)

### Summary
`Shipit::CCMenuUrlController#client` looks up the same `ApiClient` record via `find_or_create_by!(creator: current_user, name: 'CCMenu Client')`, keyed only on `creator` and `name`, never on the requested `stack_id`, so the same client (and therefore the same `authentication_token`, since `authentication_token` is deterministic from `id`) is returned regardless of `params[:stack_id]`. `Api::CCMenuController` further authorizes requests using this token against `Stack.from_param!(params[:stack_id])` directly, bypassing the `stacks` scoping helper that would otherwise restrict access when `current_api_client.stack_id` is set. Since the CCMenu `ApiClient` is created without ever setting `stack_id`, both the mint step and the use step are unscoped, so a token minted while viewing stack A is valid indefinitely and reusable against stack B.

### Finding Description
Binding claimed to be broken: `ApiClient#stack_id (at mint time for stack A)` should equal `Stack.from_param!(params[:stack_id]) (at use time)`; here, no such equality is ever enforced.

Code path:
1. `CCMenuUrlController#fetch` (app/controllers/shipit/ccmenu_url_controller.rb:7-11) builds a CCMenu URL for `stack = Stack.from_param!(params[:stack_id])`, but the token embedded is `client.authentication_token`.
2. `client` (lines 15-18) resolves via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` — the lookup/creation key is `(creator, name)` only. There is no `stack:` attribute passed, even though `Shipit::ApiClient` has an optional `belongs_to :stack` column (app/models/shipit/api_client.rb:8) that could have been used to bind the client to one stack.
3. Because the same `(creator, name)` pair is used for every stack the user views CCMenu URLs for, repeated calls to `fetch` with different `params[:stack_id]` return the identical `ApiClient` row and hence the identical `id`/`authentication_token` (`ApiClient#authentication_token`, model lines 34-36, is `message_verifier.generate(id)`).
4. When the token is presented to `Api::CCMenuController#show`, authentication happens via `ApiClient.authenticate(params[:token])` (app/controllers/shipit/api/ccmenu_controller.rb:33-36), which only verifies the signature and loads the row by `id` — it performs no stack check.
5. Authorization is `require_permission :read, :stack` (line 6), which calls `require_permission!` → `current_api_client.check_permissions!('read', 'stack')` (app/controllers/shipit/api/base_controller.rb:82-84) — this only checks the `permissions` array (`%w[read:stack]`), not `stack_id`.
6. Critically, `Api::CCMenuController` overrides `stack` (lines 29-31) to call `Stack.from_param!(params[:stack_id])` directly, instead of using `BaseController#stacks`/`#stack` (base_controller.rb:74-80), which is the only place that would have scoped by `current_api_client.stack_id` if it had been set (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`). Since the CCMenu client never has `stack_id` set anyway (step 2), this scoping mechanism is doubly bypassed.

Attacker flow: An authenticated Shipit user with `read:stack` access to two stacks A and B visits the CCMenu URL page for stack A, obtaining `token_A`. `token_A` is in fact identical to whatever `token_B` would be obtained for stack B, because both resolve to the same `ApiClient` row. The user (or anyone they leak the URL to) can call `GET /api/1/stacks/:stack_B/ccmenu.xml?token=token_A` and get a `200 OK` with stack B's status — even for a stack for which the CCMenu URL was never generated, as long as the same `read:stack`-permissioned client exists and the requester can reach `Stack.from_param!` for stack B (no per-stack membership check exists here beyond generic permission).

Existing guards examined and why they don't stop this: `require_permission!`/`check_permissions!` only check the coarse `permissions` array, not stack identity; `ApiClient.authenticate` only checks signature validity; `stacks`/`stack` scoping in `BaseController` is not used by `CCMenuController`; and `ApiClient`'s optional `belongs_to :stack` is present in the schema but simply never populated or checked for this client type.

### Impact Explanation
This is unauthorized read of another stack's build/deploy status (CCMenu project XML: name, activity, last build status/label/time, web URL) using a token nominally scoped to a different stack. It does not expose secrets or allow writes/deploys (permission is `read:stack` only, no `write`/`deploy`), so it does not reach the Critical bar (no RCE, no forged webhook/session, no secret exfiltration, no cross-repo mutation). It matches the **High** category: "unauthenticated read of stack state" in the sense that a token minted for/expected to be scoped to one stack functions as a blanket read-access token across every stack the same permission level would allow — effectively an authorization-scope bypass rather than pure unauthenticated access. The blast radius is limited to stacks the acting `ApiClient`'s permissions already generically allow (`read:stack`), and to information disclosure of build status, not credentials or deploy control.

### Likelihood Explanation
Preconditions: the user must already be an authenticated Shipit user with access to view CCMenu URLs for at least one stack (this feature is reachable via `ShipitController`, i.e., requires a logged-in session — this is not exploitable by a fully unauthenticated attacker as defined in the "attacker is unprivileged" rule, since the rule states the attacker holds no Shipit session). Given the rules explicitly state the attacker "hold[s] no Shipit session," an attacker with truly zero session/credentials cannot reach `CCMenuUrlController#fetch` at all (it's behind `ShipitController`, presumably requiring authentication) to mint a token in the first place. This significantly limits applicability under the stated threat model — the scenario requires the actor to already be a logged-in Shipit user, which is a step up from the "unprivileged internet attacker" defined in the rules.

### Recommendation
Scope the `ApiClient` to the specific stack when minting the CCMenu token, e.g. `ApiClient.create_with(permissions: %w[read:stack], stack: stack).find_or_create_by!(creator: current_user, name: "CCMenu Client (#{stack.to_param})")`, and change `Api::CCMenuController#stack` to use the inherited `stacks.from_param!(params[:stack_id])` (respecting `current_api_client.stack_id`) instead of `Stack.from_param!` directly, so a stack-bound client cannot read other stacks.

### Proof of Concept
```ruby
# test/controllers/ccmenu_url_controller_test.rb (illustrative, not exhaustive)
test "CCMenu token is shared across stacks and reusable against another stack" do
  sign_in(@user)
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.create!(owner: 'foo', name: 'bar'), branch: 'main')

  get :fetch, params: { stack_id: stack_a.to_param }
  url_a = JSON.parse(response.body)['ccmenu_url']
  token_a = Rack::Utils.parse_query(URI(url_a).query)['token']

  get :fetch, params: { stack_id: stack_b.to_param }
  url_b = JSON.parse(response.body)['ccmenu_url']
  token_b = Rack::Utils.parse_query(URI(url_b).query)['token']

  # Binding claim: ApiClient minted for stack_a should differ from the one for stack_b
  assert_equal token_a, token_b # demonstrates same underlying ApiClient/id is reused

  # Replay token minted while "viewing" stack_a against stack_b
  get "/api/1/stacks/#{stack_b.to_param}/ccmenu.xml", params: { token: token_a }
  assert_response :ok # unauthorized cross-stack read succeeds
end
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
```

**File:** app/models/shipit/api_client.rb (L34-36)
```ruby
    def authentication_token
      self.class.message_verifier.generate(id)
    end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-36)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-84)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end

      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```
