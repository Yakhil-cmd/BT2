### Title
Stack-scoped API token can read CCMenu deploy status of any stack, bypassing its `stack_id` authorization scope - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController#stack` looks up the target stack with `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!(params[:stack_id])` helper used by every other API controller. This breaks the equality that should hold between "the stack a token is authorized for" (`current_api_client.stack_id`) and "the stack the token actually touches" (`params[:stack_id]`), letting a stack-scoped `ApiClient` read deploy/CI status for any stack in the Shipit instance.

### Finding Description
`Shipit::Api::BaseController` establishes the authorization binding that every other API endpoint relies on: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is scoped to a specific stack, and `stack` resolves `params[:stack_id]` only within that restricted set — this is the binding: `token.authorized_stack == resolved_stack`.

`CCMenuController` overrides `stack` and drops this scoping entirely: [2](#0-1) 

`Stack.from_param!` performs a global lookup with no reference to `current_api_client` at all: [3](#0-2) 

So even though `require_permission :read, :stack` confirms the *permission* `read:stack` exists on the client, it never confirms the *stack* being accessed is the one the client is bound to. Any `ApiClient` with the `read:stack` permission — for example the `here_come_the_walrus` fixture, which is explicitly scoped to the `shipit` stack — can supply an arbitrary `stack_id` in the URL and receive that other stack's CCMenu payload (deploy status/history) instead of being rejected. [4](#0-3) 

Before this request: `current_api_client.stack_id` == `shipit` stack, so per the general API contract the client should only ever be able to resolve `stack == shipit`. After the request (with a different `stack_id` param): `resolved_stack != current_api_client.stack_id`, yet the request still succeeds and returns real deploy data for the unauthorized stack — the equality binding is broken.

### Impact Explanation
This is an unauthorized cross-stack read of stack state (deploy status, last deploy id, running state) via a token that was deliberately scoped to a single stack. This matches the accepted High-impact category "unauthenticated read of stack state, task streams or deploy output" in spirit — here the read occurs through a token that is authenticated but has explicitly bypassed its scope restriction, exposing deploy state of stacks the token owner should have no visibility into. In multi-tenant Shipit deployments (many repositories/environments sharing one instance), this discloses deployment cadence/status information across teams or projects that should be isolated by the `ApiClient#stack_id` binding.

### Likelihood Explanation
Any holder of a stack-scoped `read:stack` API token (a very common, low-privilege token type, e.g. issued for status dashboards/CCMenu integrations) can trigger this by simply changing the `stack_id` segment of the URL — no other privilege or secret is required beyond the token they already legitimately possess for their own stack.

### Recommendation
Change `CCMenuController#stack` to reuse the scoped lookup, consistent with the rest of the API:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the binding `current_api_client.stack_id == resolved_stack` that all other `Api::BaseController` subclasses already enforce.

### Proof of Concept
1. Create/obtain an `ApiClient` scoped to stack A (`stack_id` set to stack A's id) with `read:stack` permission (e.g. `here_come_the_walrus` fixture, scoped to the `shipit` stack).
2. Using this client's Basic Auth token, send `GET /api/stacks/<owner>/<other-stack-name>/<other-environment>/ccmenu` where the path identifies stack B, a completely different stack the client was never granted access to.
3. Observe that `CCMenuController#show` renders stack B's CCMenu XML (latest deploy id, status, running flag) successfully, because `stack` resolves via `Stack.from_param!` with no reference to `current_api_client.stack_id`, unlike every other `Api::BaseController` subclass which uses the scoped `stacks.from_param!`.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```
