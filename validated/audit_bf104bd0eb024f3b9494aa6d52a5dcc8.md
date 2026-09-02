### Title
Webhook signature verification can be bypassed for organizations without a configured `webhook_secret`, allowing forged webhooks to mutate state of *any* repository/stack — (File: `lib/shipit/github_app.rb`, `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to validate a webhook against based on an **unauthenticated** field of the incoming payload (`repository.owner.login`, falling back to `organization.login`). `GitHubApp#verify_webhook_signature` then short-circuits to `true` whenever that selected configuration has no `webhook_secret` set. Once "verified", the same raw payload is dispatched to handlers, which independently pick the repository/stack to mutate using a *different* payload field (`repository.full_name`). This breaks the binding between "the organization whose credentials were used to authenticate the request" and "the repository that is actually written to."

### Finding Description
`verify_signature` computes the organization used for verification purely from the payload body, before any cryptographic check has occurred: [1](#0-0) [2](#0-1) 

That organization name is used to fetch a `GitHubApp` instance via `Shipit.github(organization: repository_owner)` and its `webhook_secret`. Critically, `verify_webhook_signature` treats an organization with no configured secret as automatically verified, with no signature required at all: [3](#0-2) 

The `webhook_secret` is explicitly optional per-organization (`@webhook_secret = @config[:webhook_secret].presence`) in a multi-org configuration (`Shipit.github_app_config`, `Shipit.github_organizations`): [4](#0-3) [5](#0-4) 

Once `verify_signature` passes (trivially, for an org lacking a secret), `WebhooksController#create` dispatches the *entire, still-unverified* payload to event handlers: [6](#0-5) 

Handlers determine which repository/stack to act on independently, from a *different* payload field (`repository.full_name`), not from `repository.owner.login` that was used for the secret lookup: [7](#0-6) [8](#0-7) 

The equality broken: `organization used to authorize the webhook (selected by the unverified repository_owner field, and trivially "authenticated" because that org has no secret)` ≠ `repository whose stack is actually mutated (chosen by the unverified repository.full_name field)`. Because these two fields come from the same attacker-supplied JSON body and are never cross-checked against each other, an attacker can pick any org with no secret configured to satisfy `verify_signature`, while pointing `repository.full_name` at a completely different, victim repository/stack that does have secrets configured (and thus is otherwise believed to be protected).

### Impact Explanation
This allows an unauthenticated caller to inject fabricated GitHub events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) against arbitrary stacks unrelated to the org that nominally "verified." For example, the `status` handler creates a `Status` on a targeted commit using attacker-controlled `state`/`context`/`description`, which can fabricate a passing CI check on a victim repository's commit — a check operators may rely on before triggering a real deploy, leading to an unauthorized deploy. Other handlers (`push`, `check_suite`, `pull_request`) similarly enqueue jobs that mutate the state of a stack/repository never intended to be reachable by that "verification path." This matches the Critical impact category ("unauthorized deploy, rollback or merge").

### Likelihood Explanation
Exploitability depends on at least one configured GitHub organization in `secrets.github` lacking a `webhook_secret` — a state explicitly supported by the engine's own code (`.presence` fallback, per-organization config map) rather than a deviation from documented deployment. In any Shipit instance managing multiple GitHub organizations where even one org's webhook secret is not set (e.g., partially onboarded org, or an org intentionally left unauthenticated because "nothing sensitive" lives there), any unauthenticated internet client can exploit this to affect completely unrelated, sensitive repositories/stacks.

### Recommendation
Do not let the choice of which secret to verify against be self-selected by an unauthenticated payload field whose trust outcome ("no secret configured -> auto-pass") can be leveraged to bypass verification for events describing a *different* repository. Concretely: (1) require every configured organization to have a non-blank `webhook_secret` (fail closed, not open, when absent) instead of `return true unless webhook_secret`; and (2) after signature verification, assert that `repository.owner.login`/`organization.login` (the field used to pick the verifying secret) matches the `repository.full_name` owner actually used by handlers, rejecting mismatches.

### Proof of Concept
1. Shipit is configured with `secrets.github` containing two orgs: `victim-org` (has `webhook_secret` set, hosts a real, sensitive stack) and `sandbox-org` (no `webhook_secret` configured, e.g. an org onboarded without secret rotation yet).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: status`, no `X-Hub-Signature` (or a garbage one), and JSON body:
```json
{
  "repository": { "owner": { "login": "sandbox-org" }, "full_name": "victim-org/critical-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/build",
  "description": "forged status"
}
```
3. `verify_signature` resolves `repository_owner` = `"sandbox-org"` from the payload, looks up its `GitHubApp`, and `verify_webhook_signature` returns `true` unconditionally because `sandbox-org` has no `webhook_secret`.
4. `create` dispatches the payload to the `status` handler, which uses `repository.full_name` = `"victim-org/critical-repo"` to locate the real, protected stack/commit and creates a fabricated passing `Status`, despite the attacker never having any credential for `victim-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** lib/shipit.rb (L190-200)
```ruby
  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
