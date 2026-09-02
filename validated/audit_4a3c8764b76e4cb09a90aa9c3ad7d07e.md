### Title
CCMenu controller ignores API-client stack scoping, allowing a stack-scoped token to read any other stack's build status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` defines its own private `stack` method that calls `Stack.from_param!(params[:stack_id])` directly on the `Stack` model, instead of using the scoped `stacks.from_param!` inherited from `BaseController`. As a result, any valid `ApiClient` token — even one that is explicitly scoped to a single stack via `stack_id` — can be used to read the CCMenu build status of an arbitrary, unrelated stack simply by changing the `stack_id` request parameter.

### Finding Description
The broken binding is: `current_api_client.stack_id? ? current_api_client.stack_id == stack.id : true` — this equality is enforced everywhere else in the API but **not** in `CCMenuController`.

`BaseController` establishes the intended scoping contract: [1](#0-0) 
`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the client is scoped (`stack_id?` is true — an ActiveRecord attribute predicate on the `stack_id` column), and `stack` resolves `params[:stack_id]` only within that restricted relation.

`CCMenuController`, however, overrides `stack` to bypass this entirely: [2](#0-1) 
It authenticates via `ApiClient.authenticate(params[:token])` (query-string token, not `BasicAuth`) and then calls `Stack.from_param!(params[:stack_id])` — resolving against **all** stacks, ignoring `current_api_client.stack_id`.

Exploit flow:
1. A stack-scoped `ApiClient` token exists for Stack A — created either through the admin `api_clients` resource (`stack_id` set) or via `CCMenuUrlController#fetch`, which mints a `read:stack` client and embeds the token directly in a CCMenu URL query string: `uri.query = { 'token' => client.authentication_token }.to_query` [3](#0-2) .
2. That URL is leaked (Referer header, browser history, shared link, screenshot) to the attacker, who now holds a valid token for Stack A only.
3. The attacker requests `GET /api/stacks/*stack_id/ccmenu?token=<leaked_token>` but substitutes Stack B's `stack_id`.
4. `authenticate_api_client` accepts the token (it's a valid, unexpired `ApiClient`), and `require_permission :read, :stack` passes because the client does have `read:stack` permission — that check is scope-agnostic. `stack` then resolves Stack B via the unscoped `Stack.from_param!`, and `show` renders Stack B's name, last build status/label/time and web URL.

Existing guards (`require_permission`, `check_permissions!`) only check the operation/scope pair (`read:stack`), never the per-record `stack_id` binding; that binding is enforced solely by `BaseController#stacks`/`#stack`, which `CCMenuController` deliberately shadows.

### Impact Explanation
An attacker holding any single stack-scoped (or unscoped read-only) CCMenu/API-client token can enumerate and read the build status, last build label, last build time, activity, and web URL of every stack in the Shipit instance, not just the one the token was minted for. This is a cross-tenant unauthorized read of stack state, matching the High severity category "unauthenticated read of stack state" since the token was never authorized for the target stack. It is fully repeatable (one HTTP GET per stack) and works across arbitrary stack IDs the attacker can guess or enumerate via `Stack#to_param` (owner/repo/branch format).

### Likelihood Explanation
The attacker needs one leaked/obtained `ApiClient` token with `read:stack` permission (commonly distributed as a CCMenu URL query-string parameter, which is inherently prone to leaking via Referer headers, logs, or browser history). No GitHub secrets, session, or privileged role is required — only possession of any one valid token, regardless of its intended stack scope. This is a low-cost, easily repeatable attack once a single token is obtained.

### Recommendation
Make `CCMenuController#stack` honor the same scoping as `BaseController`, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
removing the local override so it inherits the scoped `stacks` relation, ensuring `current_api_client.stack_id` is enforced.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a token scoped to one stack cannot read another stack via ccmenu" do
  scoped_client = shipit_api_clients(:here_come_the_walrus) # stack: shipit, permissions: [read:stack]
  other_stack = shipit_stacks(:cyclimse) # any stack != scoped_client.stack

  get :show, params: { stack_id: other_stack.to_param, token: scoped_client.authentication_token }

  # BEFORE fix: request succeeds and returns other_stack's data
  # AFTER fix: request should be rejected (404/403), since
  # scoped_client.stack_id != other_stack.id
  assert_response :not_found # or :forbidden, once scoping is enforced
end
```
Currently this test would fail (return `200 OK` with `other_stack`'s XML payload), demonstrating the scope bypass; asserting `assert_response :ok` and `assert_payload 'name', other_stack.to_param` before the fix proves the vulnerability.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-11)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end
```
