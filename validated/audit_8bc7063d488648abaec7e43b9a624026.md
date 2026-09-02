## Analysis

Confirmed: in a multi-organization Shipit deployment (`config/secrets.*.yml` supports a `github: { OrgOne: {...}, OrgTwo: {...} }` schema), each configured GitHub organization has its own independent `webhook_secret`. [1](#0-0) 

The webhook signature check selects **which** organization's secret to verify against using a field taken directly from the untrusted, attacker-suppliable JSON body — `repository.owner.login` (or `organization.login`) — *before* the signature has been validated: [2](#0-1) [3](#0-2) 

Once `verify_webhook_signature` passes, the event is dispatched to handlers unchanged. Every handler determines the **actual target repository/stack to mutate** using a *different* field from the same payload — `repository.full_name`: [4](#0-3) [5](#0-4) 

Because HMAC verification only proves "this byte-for-byte body was signed by *some* org's configured secret" and the org used to pick that secret (`repository.owner.login`) is decoupled from the org/repo actually acted upon (`repository.full_name`), an attacker who legitimately controls the webhook secret for **one** configured organization (e.g., they administer their own GitHub org that a shared multi-tenant Shipit instance also serves, and know/set that org's `webhook_secret`) can forge a POST to `/webhooks` where:
- `repository.owner.login` = their own org (so `Shipit.github(organization: repository_owner)` returns *their* `GitHubApp` and the HMAC they computed with their own secret validates), while
- `repository.full_name` = `victim-org/victim-repo`, a completely different organization/repository hosted on the same Shipit instance whose webhook secret they do not know.

The `PushHandler` (and other handlers) will then locate the victim's `Stack` via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and enqueue `sync_github`/`archive!`/`unarchive!` etc. against it — all without ever knowing the victim organization's real webhook secret.

## Binding broken

**Equality that should hold:** `organization whose secret authenticated the request == organization/repository the handler writes to`.
**What actually happens:** the field selecting the *authenticating* org (`repository.owner.login`, read pre-verification) is independent of the field selecting the *written* repository (`repository.full_name`), and both are attacker-controlled in the raw JSON body — only their *consistency* is unverified.

This is a structural analog of the Hats Protocol bug: a state/authority reference (`toggle` address / here, "which org's secret to check") is switched based on unverified attacker input, while the actual state acted upon (`hat` status / here, "which stack gets mutated") is taken from a different, decoupled reference in the same request.

## Assessment

This requires the attacker to control at least one organization/repository already configured and installed in a shared, multi-tenant Shipit instance (i.e., they must know a real `webhook_secret` for *some* org in the config) — this is a normal, unprivileged position for a tenant on a shared instance, not a Shipit session, `ApiClient` token, or `github_access_token`, so it is not excluded by the "requires a privileged account" rule. The impact — an unauthenticated-with-respect-to-the-target-org cross-repository write (triggering syncs, archiving/unarchiving stacks, closing PRs, etc. on a repository the attacker's signing key was never issued for) — matches the in-scope Critical impact "cross-repository writes."

### Title
Webhook organization used for signature-secret selection is decoupled from the repository the handler writes to, enabling cross-organization forged webhooks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to check against using `repository.owner.login` read straight out of the unverified JSON body, while every `Webhooks::Handlers::Handler` subclass determines the actual `Stack`/`Repository` to act on using the independent `repository.full_name` field from the same body. Nothing binds these two fields together.

### Finding Description
`repository_owner` is computed from attacker-controlled JSON before any signature check: [3](#0-2)  and is fed into `Shipit.github(organization: repository_owner)` to select the `GitHubApp`/`webhook_secret` used for verification: [6](#0-5) , backed by per-org secrets in `lib/shipit.rb#github`/`#github_app_config`: [1](#0-0) .

Once the HMAC passes, `create` hands the full parsed body to handlers: [7](#0-6) . Handlers ignore `repository.owner.login` entirely and instead resolve the target repository/stack from `repository.full_name`: [4](#0-3) , then act on it, e.g. triggering a GitHub sync job for matching stacks: [8](#0-7) .

Because the signature only certifies "signed by the secret belonging to whatever `repository.owner.login` says," and the actual mutation target is looked up via the unrelated `repository.full_name`, an attacker who owns/administers Org A (and thus legitimately knows Org A's `webhook_secret` in a shared multi-tenant Shipit deployment) can set `repository.owner.login = "OrgA"` (so verification passes using their own secret) but `repository.full_name = "OrgB/victim-repo"`, forging events against Org B's stacks without ever needing Org B's secret.

### Impact Explanation
This breaks the trust boundary between tenants of a shared Shipit instance: possession of one organization's webhook secret becomes sufficient to forge push/pull_request/status/membership events against any *other* organization's repositories tracked by the same instance, triggering unauthorized syncs, PR-driven review-stack archive/unarchive actions, and status writes — a cross-repository write achieved without the credentials that are supposed to gate that repository.

### Likelihood Explanation
Requires only that the attacker already has legitimate configuration of at least one org in the Shipit multi-tenant `github:` secrets map (a normal, unprivileged tenant position, not a Shipit session, API token, or private key) and that other organizations are configured on the same instance — a documented, supported setup (`config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`). No cryptographic break is needed; the attacker signs their own forged payload with their own legitimate secret.

### Recommendation
After `verify_webhook_signature` succeeds using the secret selected via `repository.owner.login`, re-validate that `repository.full_name` (or `organization.login`, for org-scoped events) actually belongs to the same authenticated organization before dispatching to handlers — e.g., assert `payload.dig('repository','full_name')&.split('/')&.first&.downcase == repository_owner.downcase` and reject (422) on mismatch.

### Proof of Concept
1. Deploy Shipit with multi-org config: `OrgA` (secret known to attacker, who administers OrgA on GitHub) and `OrgB` (victim, secret unknown to attacker), both with repos tracked as Shipit stacks.
2. Attacker crafts a `push` payload: `{"ref": "refs/heads/main", "after": "<victim sha>", "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/victim-repo"}}`.
3. Attacker computes `X-Hub-Signature` using OrgA's `webhook_secret` (which they legitimately know) over this exact body.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `repository_owner => "OrgA"`, fetches OrgA's `GitHubApp`, and the HMAC validates.
5. `PushHandler#process` resolves the stack via `repository.full_name = "OrgB/victim-repo"` and enqueues `stack.sync_github(expected_head_sha: "<victim sha>")` against OrgB's stack — a write triggered without ever presenting OrgB's webhook secret. [5](#0-4)

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
