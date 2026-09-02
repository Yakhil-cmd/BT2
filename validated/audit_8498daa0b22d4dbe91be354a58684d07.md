## Title
Cross-organization webhook forgery via signing-org/written-repository mismatch in `verify_signature` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-organization Shipit deployments (`secrets.github` keyed by org, e.g. `test/dummy/config/secrets_double_github_app.yml`), each organization has its own GitHub App and its own `webhook_secret`. `WebhooksController#verify_signature` picks *which* secret to verify the HMAC against by reading `repository.owner.login` (or `organization.login`) out of the *same untrusted JSON body* whose signature it is about to check, then hands the *entire* parsed body — including any other `repository.full_name` value — to the event handlers. Nothing ties the organization whose secret validated the signature to the repository the handlers subsequently act on.

### Finding Description
`verify_signature` resolves the signing key purely from attacker-controlled payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up the per-organization config/secret from `secrets.github`: [3](#0-2) 

Once `verify_signature` succeeds (i.e. the HMAC matches org **A**'s `webhook_secret`, because the attacker legitimately knows/controls org A's GitHub App secret — they are the admin who registered org A's App with this Shipit instance), the raw JSON is parsed again and dispatched unmodified to handlers: [4](#0-3) 

Handlers derive the target repository from a *different* field of the same JSON body — `repository.full_name` — with no comparison back to the `repository.owner.login`/`organization.login` value that was used to select the verification secret: [5](#0-4) [6](#0-5) [7](#0-6) 

Because HMAC-SHA1 is computed over the *entire* raw request body, and `repository.owner.login` and `repository.full_name` are two independent keys inside that same body, the attacker who owns org A's `webhook_secret` can construct a payload where:
- `repository.owner.login` = `"OrgA"` (so `verify_signature` selects OrgA's secret and the HMAC — signed by the attacker themselves — validates), while
- `repository.full_name` = `"OrgB/some-repo"` (an entirely unrelated organization/repository configured on the same Shipit instance).

The binding that should hold is:
`organization whose secret authenticated the request == organization that owns the repository the handler mutates`

but nothing in `verify_signature` or `Handler#repository_name`/`PushHandler#process`/`StatusHandler#process` enforces it. This is a cross-tenant confusion, not a stolen-secret attack — analogous to the MOKE report's pattern where an unprivileged, self-authenticated caller (the attacker signing/authorizing their own transaction) reaches internal state belonging to someone else because a binding between "who authorized" and "what got acted on" was never checked.

### Impact Explanation
An attacker who legitimately controls one organization's GitHub App / webhook secret on a shared, multi-org Shipit instance can forge `push` and `status` webhooks that are processed as if they came from GitHub for **any other organization's repository** configured on the same instance:
- Forged `push` events trigger `Stack#sync_github(expected_head_sha:)` for stacks belonging to a different org — this drives `GithubSyncJob`, influencing which commits Shipit considers deployable/undeployed for that stack.
- Forged `status` events let the attacker inject arbitrary CI status (`state`, `context`, `target_url`, `description`) onto commits of another organization's stack via `Commit#create_status_from_github!`, which can flip Shipit's CI-gating logic (`ci.require`/`ci.allow_failures`) and enable an unauthorized deploy of that other organization's stack.

This crosses the "cross-repository writes" / "unauthorized deploy" bar called out as Critical impact, without the attacker ever needing write access, an `ApiClient` token, or a stolen secret belonging to the victim org — only a webhook secret for their own tenant.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (explicitly supported and documented: `test/dummy/config/secrets_double_github_app.yml`, `config/secrets.development.shopify.yml`) where at least two organizations' GitHub Apps are configured. Any user who is an admin of one tenant's GitHub App (a routine, low-privilege administrative capability, not a Shipit account) can exploit this by crafting a raw HTTP POST with a mismatched `repository.owner.login` vs `repository.full_name`, signed with their own known secret — no Shipit login, `ApiClient` token, or victim-side secret needed.

### Recommendation
In `WebhooksController#verify_signature`, after determining `repository_owner` and validating the signature, re-derive the repository/organization that handlers will use (`repository.full_name`'s owner segment, or `organization.login`) and reject the request (422) unless it matches the organization whose secret validated the signature. Alternatively, bind `Handler#repository_name` lookups to the already-verified `repository_owner` rather than trusting `repository.full_name` independently.

### Proof of Concept
1. Attacker administers org `OrgA`'s GitHub App on a shared Shipit instance also serving `OrgB`, and knows `OrgA`'s `webhook_secret`.
2. Attacker builds a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "OrgA")` and the HMAC validates (attacker knows the key) — request passes.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: params.after)` on OrgB's stack, despite the request having been authenticated only against OrgA's secret.

**Uncertainty**: I could not fully verify from the indexed code whether `Repository.from_github_repo_name` performs any additional cross-checks against the organization that signed the request (e.g., a `github_id`/installation binding on `Repository` or `GithubHook`) that might mitigate this at a lower layer — `app/models/shipit/github_hook.rb` and `app/models/shipit/repository.rb` were referenced but their full contents were not retrieved in this session. If such a binding exists there, it could narrow or eliminate this finding; a Devin session with full repo access should confirm `Repository.from_github_repo_name` and `GithubHook` semantics before treating this as conclusively exploitable.

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
