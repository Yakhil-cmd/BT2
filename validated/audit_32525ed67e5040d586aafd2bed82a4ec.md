This confirms the key finding: multi-tenant Shipit deployments configure **per-organization** webhook secrets via `Shipit.github_app_config`, keyed by the organization name found in the config keys [1](#0-0) . The `WebhooksController#verify_signature` selects which secret to verify against using `repository_owner`, which is read from the **unverified** JSON body before the signature is checked [2](#0-1) , falling back to `organization.login` if `repository` is absent [3](#0-2) . Once the signature is accepted, every event handler (e.g. `PushHandler`, the `PullRequest` handlers) independently re-derives the target repository from `payload.dig('repository', 'full_name')` and resolves it via `Repository.from_github_repo_name` [4](#0-3) [5](#0-4) .

Because `repository.owner.login` (used to pick the HMAC secret) and `repository.full_name` (used to pick the stack that actually gets written to — new commits appended, review stacks archived/unarchived, PR labels captured, etc.) are two **separate, independently attacker-controlled fields in the same unsigned-until-verified JSON body**, they are never bound together by anything the signature enforces beyond "this exact byte sequence was HMAC'd with organization A's secret." A tenant who administers a Shipit-connected repository under organization "attacker-org" knows that org's `webhook_secret` (it's the org admin's own webhook config) and can therefore compute a valid `X-Hub-Signature` for a payload where `repository.owner.login = "attacker-org"` (so `verify_signature` selects and passes with `attacker-org`'s secret) while `repository.full_name = "victim-org/victim-repo"` (so `PushHandler`/`Repository.from_github_repo_name` resolves and mutates the victim's stack). This lets an attacker forge push/pull_request/status/check_suite events against **any repository configured in the same Shipit instance**, e.g. injecting fabricated commits via `GithubSyncJob`, or flipping `ReviewStack` archive state, on a repo they do not own and have no GitHub webhook secret for.

This matches the requested analog class exactly: *"an organization that authenticated versus the repository that is written."* The `repository_owner` value is verified (drives which secret validates the signature) but the `full_name` value that the handlers actually act on is never covered by that check — it's merely read from the same trusted-because-HMAC'd blob whose HMAC only vouches for byte-for-byte content, not for the semantic consistency between `owner.login` and `full_name`.

### Title
Webhook signature is verified per-organization using `repository.owner.login`, but handlers act on the independently attacker-controlled `repository.full_name`, allowing cross-repository event forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` chooses which organization's `webhook_secret` to validate an inbound GitHub webhook against by reading `repository.owner.login` (or `organization.login`) straight out of the unauthenticated JSON body. All downstream `Shipit::Webhooks::Handlers` (push, pull_request, etc.) instead resolve the target `Stack`/`Repository` using `repository.full_name` from that same body. Nothing ties `owner.login` to `full_name`, so a valid signature computed with organization A's secret can be attached to a payload whose `full_name` points at organization B's repository, and the handler will act on organization B's stack.

### Finding Description
`verify_signature` computes `repository_owner` from the raw, not-yet-verified body [3](#0-2) , uses it to fetch the corresponding `GitHubApp` config via `Shipit.github(organization:)` [6](#0-5) , and only then calls `verify_webhook_signature`, which performs a plain HMAC-SHA1 comparison over the entire raw body with that organization's `webhook_secret` [7](#0-6) . The HMAC proves the body wasn't tampered with relative to organization A's secret; it says nothing about whether `full_name` inside that body actually belongs to organization A.

Every handler, however, keys off `full_name`, not `owner.login`, to find the affected repository/stack: `Handler#stacks` calls `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')` [4](#0-3) ; `PushHandler#process` then syncs any non-archived stacks under that repository [8](#0-7) . `Repository.from_github_repo_name` simply splits `owner/name` from the string and looks up the record, with no cross-check against the signing organization [5](#0-4) . Pull-request handlers (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabelCapturingHandler`) do the same [9](#0-8) .

This is the same class of bug as the reported `NFTMintSaleMultiple` issue: two independent code paths each trust a different, non-cross-checked identifier out of the same input (there, an ID range guarded by one minter but writable by another; here, an authenticating org field and an acted-upon repo field), and their disagreement lets one authority's credential be used to affect the other's resource.

### Impact Explanation
An attacker who legitimately administers a Shipit-connected GitHub organization (and therefore knows that org's configured `webhook_secret`) can forge a valid `X-Hub-Signature` for a crafted `push`, `pull_request`, `status`, or `check_suite` payload whose `repository.full_name` targets a different tenant's repository on the same Shipit instance. This lets them:
- Trigger `GithubSyncJob`/`append_commit` to inject attacker-chosen commit SHAs into a victim stack's commit history, which can influence what gets deployed.
- Force `ReviewStack#archive!`/`unarchive!` on a victim's review stacks.
- Inject fabricated commit statuses/labels affecting deployability checks on a victim repository.

This is a cross-repository write achieved purely by exploiting the mismatch between the signature-selection key and the action-target key, without needing the victim organization's webhook secret, `ApiClient` token, or any Shipit session.

### Likelihood Explanation
Requires the Shipit instance to be configured for multiple organizations (the per-organization `secrets.github` schema described in `lib/shipit.rb`), which is a documented, first-class supported deployment mode [10](#0-9) . Any tenant/organization owner already onboarded to that shared instance — a low, plausible privilege level, and explicitly not one of the excluded "requires a privileged account" scenarios since organization-level GitHub App/webhook configuration is the normal, expected access level for a tenant — can mount the attack purely by crafting an HTTP request; no further privilege escalation, session, or secret theft is needed.

### Recommendation
After verifying the signature, re-derive (or cross-validate) the organization implied by `repository.full_name`/`organization.login` used by the handlers against the organization whose secret validated the signature, and reject the webhook if they diverge. Alternatively, bind the webhook secret lookup and the resource-resolution lookup to the same single field (e.g. always use `full_name`'s owner segment for secret selection) so the two can never disagree.

### Proof of Concept
1. Shipit is configured with two tenant organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` under `secrets.github`.
2. Attacker, who administers `attacker-org` and knows its `webhook_secret`, builds a `push` payload:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>",
     "repository": {
       "full_name": "victim-org/victim-repo",
       "owner": { "login": "attacker-org" }
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_of_attacker_org, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` reads `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `webhook_secret`, and the HMAC check passes [6](#0-5) .
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `GithubSyncJob` for the victim's stack with the attacker-supplied `expected_head_sha` [8](#0-7) , despite the attacker having no legitimate relationship with `victim-org`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
