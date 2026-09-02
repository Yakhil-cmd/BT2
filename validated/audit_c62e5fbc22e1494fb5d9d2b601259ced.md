### Title
Webhook signature is bound to the payload's organization identity but not to the `repository.full_name` that handlers act on, allowing cross-organization forged deploy/CI events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using `repository_owner`, a value read straight out of the untrusted JSON body (`repository.owner.login`, falling back to `organization.login`), while the code that actually decides *which Shipit-tracked repository/stack gets written to* uses a different field from the same body, `repository.full_name`, via `Handler#repository_name` and `Repository.from_github_repo_name`. The equality the engine implicitly relies on — "the organization whose secret authenticated this request" == "the organization that owns the repository being written" — is never enforced.

### Finding Description
`verify_signature` picks the app/secret to check with: [1](#0-0) 

`repository_owner` is derived purely from the request body: [2](#0-1) 

`Shipit.github(organization:)` looks up a per-organization `webhook_secret` from the multi-tenant GitHub configuration: [3](#0-2) 

Once the signature check passes, `create` blindly hands the *entire* parsed body to the registered handlers: [4](#0-3) 

Every handler resolves the target repository/stacks not from `repository_owner` (the field that was cryptographically checked) but from `repository.full_name`: [5](#0-4) 

`Repository.from_github_repo_name` then splits that attacker-controlled string on `/` and does a plain DB lookup, with no cross-check against `repository_owner`: [6](#0-5) 

Because the HMAC only proves "the sender knows organization A's `webhook_secret`", not "this payload actually originates from organization A's repositories", a party who possesses (or can trigger deliveries with) organization A's webhook secret can submit a JSON body where `repository.owner.login`/`organization.login` = `"org-a"` (so the signature check passes against org A's secret) but `repository.full_name` = `"org-b/production-app"` (a completely different, unrelated stack tracked by Shipit). The signature never covers this binding, so the mismatch goes undetected, exactly mirroring the BendDAO pattern where `underlyingAsset.safeTransferFrom` was gated on a value (`nftOwner`'s ongoing approval) that was decoupled from the actual debt-clearing logic that mattered for closing the position — here, the "approval" (signature) is decoupled from the "position" (repository) actually mutated.

### Impact Explanation
Via `push` and `status` events, this can enqueue `GithubSyncJob` for an arbitrary stack and forge commit statuses on arbitrary commits belonging to a stack the attacker's organization has no legitimate relationship with. Forged/manipulated CI statuses feed directly into Shipit's CI-gating and merge-queue logic (`ci.require`, `merge.require` in `shipit.yml`), which can unblock continuous-deployment paths and cause an **unauthorized deploy** of a stack the attacker does not control — satisfying the High-impact bar ("escalation ... unauthorized deploy") defined for this analysis.

### Likelihood Explanation
Exploitation requires the attacker to control (or forge/replay with) the `webhook_secret` of at least one organization configured in Shipit's multi-tenant GitHub settings — plausible in shared/multi-tenant Shipit deployments where different organizations are onboarded with separate GitHub Apps/secrets, since an org's own administrators legitimately hold their own org's secret but should have zero trust relationship with other organizations' stacks. No GitHub repository write access, Shipit session, or `ApiClient` token is required — only the ability to produce a validly-signed request body under one recognized organization's secret, which is a materially weaker requirement than the intended trust boundary.

### Recommendation
After signature verification, re-derive the organization implied by `repository.full_name` (or `repository.owner.login`) and require it to equal the organization (`repository_owner`) whose secret validated the signature before dispatching to any handler; reject the webhook (422) on mismatch instead of trusting `full_name` unconditionally in `Handler#repository_name` / `Repository.from_github_repo_name`.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` and `org-b`, each with a distinct GitHub App `webhook_secret` (per `Shipit.github_app_config`).
2. `org-a`'s legitimate webhook delivery credentials (its `webhook_secret`) are available to the attacker (e.g. an `org-a` admin who is unprivileged with respect to `org-b`).
3. Attacker crafts a `push` (or `status`) payload:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/production-app" },
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>"
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(org-a secret, raw_body)` and POSTs to `/github/webhooks`.
5. `verify_signature` resolves `repository_owner` = `"org-a"`, fetches `Shipit.github(organization: "org-a")`, and the HMAC check succeeds.
6. `Shipit::Webhooks.for_event('push').each { |handler| handler.call(params) }` runs; the push handler resolves `repository_name = "org-b/production-app"` via `Handler#repository_name`, looks up `Repository.from_github_repo_name("org-b/production-app")`, and enqueues `GithubSyncJob` / records a status on `org-b`'s stack — despite the signature never having authenticated anything about `org-b`.

### Citations

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
