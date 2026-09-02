### Title
CCMenu API tokens are not scoped to the stack they were issued for, allowing any leaked "CI status" token to read every stack's deploy state - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`CCMenuUrlController#fetch` (`app/controllers/shipit/ccmenu_url_controller.rb`) mints a per-stack "CCMenu URL" containing an `ApiClient` bearer token that is meant to expose a *single* stack's build status to an external, unauthenticated CI dashboard tool. However, the underlying `ApiClient` is created without any `stack:` binding, and the consuming controller, `Shipit::Api::CCMenuController`, resolves the target stack straight from the request's `stack_id` parameter instead of the stack the token was scoped to. The token therefore authorizes read access to the *entire* Shipit installation's stack state, not just the stack for which it was generated — a mismatch between "the stack a token authorizes" and "the stack it touches."

### Finding Description
`CCMenuUrlController#client` creates (or reuses) a single `ApiClient` per user with `read:stack` permission and **no stack scope**: [1](#0-0) 

```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
```

Note that `stack:` is never passed to `create_with`/`find_or_create_by!`, so `ApiClient#stack_id` is `nil` for this token, and the same "CCMenu Client" record (and therefore the same bearer token) is reused across every stack for which the user requests a CCMenu URL (`find_or_create_by!` matches only on `creator` + `name`).

The token is then embedded, per-stack, in a URL meant for external CI dashboard tools: [2](#0-1) 

The consuming endpoint, `Api::CCMenuController`, authenticates via this token alone (no session, no basic auth) and overrides the base scoping logic to resolve the stack directly from the request parameter: [3](#0-2) 

```ruby
def show
  latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
  render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
end

private

def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
```

Compare this to `Api::BaseController`, which every other API controller relies on to enforce the token's stack scope: [4](#0-3) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

`Api::CCMenuController#stack` bypasses this entirely, calling the unscoped `Stack.from_param!` class method directly rather than the `stacks` scope that would honor `current_api_client.stack_id`. Even if the base `stack`/`stacks` method were used unmodified, the check would still be a no-op here, because `CCMenuUrlController#client` never assigns `stack_id` on the `ApiClient` in the first place — `current_api_client.stack_id?` would always be `false`, granting `Stack.all`.

The equality/binding that should hold is:
`stack the token authorizes (the one it was minted for in the settings page) == stack the request touches (params[:stack_id])`

Both halves of this equality are broken: the token is minted unscoped, and the controller ignores scope even when present. As a result, `params[:token]` — a value designed to be published on a public, unauthenticated CI status badge for one stack — is a valid credential to read `stack.deploys_and_rollbacks.last` (deploy status, revision, timing) for **every** stack ever created in the Shipit instance, by simply substituting a different `stack_id` in the URL.

### Impact Explanation
This is an unauthenticated read of stack/deploy state for arbitrary stacks using a credential that was only meant to expose one stack's public CI badge. This matches the in-scope High-severity impact category "unauthenticated read of stack state, task streams or deploy output": anyone who obtains one CCMenu token (which is explicitly designed for embedding into third-party public dashboards, and is not treated as a secret by the UI) can iterate over every `owner/repo/environment` path in the target Shipit installation and read the latest deploy/rollback status for stacks they were never granted access to.

### Likelihood Explanation
Likelihood is elevated by the intended distribution channel of this exact token: `ccmenu_url` is designed to be pasted into third‑party CI dashboard software (CCMenu clients), i.e., it is expected to leave the trusted browser session and be stored/transmitted by other tools, exactly the kind of "unprivileged possessor of a narrow credential" scenario the analog rule targets. No GitHub write access, no Shipit login, and no privileged Shipit session is required to exploit this — only knowledge of a single previously-issued CCMenu token and the ability to enumerate/guess other stacks' `owner/repo/environment` identifiers (which are visible in the Shipit UI stack list to any authenticated team member, and often follow predictable repo/environment naming).

### Recommendation
- When creating the CCMenu `ApiClient`, always bind it to the specific stack it is generated for: `ApiClient.create_with(permissions: %w[read:stack], stack:).find_or_create_by!(creator: current_user, stack:, name: 'CCMenu Client')` (or otherwise key the `find_or_create_by!` lookup on `stack` as well as `creator`/`name`), so each stack gets its own independent token.
- Remove `Api::CCMenuController#stack`'s override and instead reuse `Api::BaseController#stack`/`#stacks`, which honors `current_api_client.stack_id`, so a stack-scoped token cannot be replayed against a different `stack_id`.
- Add a regression test asserting that a CCMenu token minted for stack A returns 403/404 when used against stack B's `stack_id`.

### Proof of Concept
1. As any Shipit-authenticated team member, visit stack A's settings page and click "Fetch URL" to mint a CCMenu URL; this calls `CCMenuUrlController#fetch`, creating an unscoped `ApiClient` (name: "CCMenu Client", `stack_id: nil`) and returning `.../services/ping/{owner}/{repoA}/{envA}.xml?token=<TOKEN>`.
2. Publish or leak `<TOKEN>` (its very purpose is to be placed in an external, unauthenticated CI dashboard tool).
3. An unauthenticated third party who obtained `<TOKEN>` requests `GET .../services/ping/{owner}/{repoB}/{envB}.xml?token=<TOKEN>` for an unrelated stack B.
4. `Api::CCMenuController#authenticate_api_client` succeeds because the token is valid (`ApiClient.authenticate(params[:token])`), and `#stack` resolves stack B directly via `Stack.from_param!(params[:stack_id])`, ignoring that the client is not scoped to stack B (or to anything at all).
5. The response renders stack B's latest deploy/rollback status — data the token holder was never authorized to see.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-12)
```ruby
  class CCMenuUrlController < ShipitController
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
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
