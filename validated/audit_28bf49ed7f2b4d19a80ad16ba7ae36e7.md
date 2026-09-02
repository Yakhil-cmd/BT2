### Title
Webhook signature verification uses an attacker-controlled organization field, decoupled from the repository the event actually mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate an inbound webhook against using `repository_owner`, a value read directly out of the *unverified* JSON body (`params.dig('repository','owner','login')`). The event handlers (e.g. `StatusHandler`, `PushHandler`) instead resolve the target `Commit`/`Repository`/`Stack` using other fields from that same unverified body (`sha`, `repository.full_name`). Nothing ties these two fields together, so a payload can be signed with one organization's `webhook_secret` while acting on a repository/commit belonging to a different, unrelated organization configured in the same Shipit instance.

### Finding Description
In a multi-organization deployment (`docs/setup.md` "Using Multiple Github Applications", `config/secrets.development.shopify.yml`), Shipit stores one `webhook_secret` per GitHub organization: [1](#0-0) 

The webhook entry point picks the app/secret to verify against purely from an unauthenticated field of the request body: [2](#0-1) [3](#0-2) 

`GitHubApp#verify_webhook_signature` only checks the HMAC against the secret picked for that `repository_owner` string — it never checks that this organization is also the owner of the repository/commit the event will subsequently mutate: [4](#0-3) 

Once verification passes, handlers act on completely different, attacker-chosen fields of the same payload. For example, `StatusHandler` looks up commits purely by `sha`, with no repository/organization cross-check at all: [5](#0-4) 

and `PushHandler`/the generic `Handler` base class resolve the target `Repository`/`Stack` from `repository.full_name`, a field independent from `repository.owner.login` used at the signature stage: [6](#0-5) [7](#0-6) 

This is the same class of bug as the referenced report (a value that is checked/authorized is not the same value that is subsequently acted upon): the **organization whose secret authenticated the request** is not equal to **the organization/repository whose data is mutated by the handler**, i.e. `verified_org(payload.repository.owner.login) != acted_on_repo(payload.repository.full_name)` is never enforced.

### Impact Explanation
If a Shipit instance is configured with multiple GitHub organizations (a documented, supported configuration), a party who legitimately controls the `webhook_secret` for **one** configured organization (e.g. they administer the GitHub App/webhook for `OrgTwo`) can sign a payload with `OrgTwo`'s secret while setting `repository.full_name`/`sha` to reference a stack, commit, or repository that belongs to `OrgOne`. Passing `verify_signature` this way lets them:
- Inject fabricated commit statuses (`StatusHandler` → `Commit#create_status_from_github!`) for arbitrary commits identified only by `sha`, potentially flipping CI/merge-gating status checks used by Shipit's merge queue for a repository they do not own — this can enable an unauthorized merge/deploy decision.
- Trigger `GithubSyncJob`/`stack.sync_github` and other handlers for stacks in an org they have no legitimate relationship with, using only knowledge of a sibling org's webhook secret.

Because a manipulated commit status can influence Shipit's merge/deploy gating for a repository the attacker does not control, this crosses into "an unauthorized deploy, rollback or merge" per the accepted impact categories.

### Likelihood Explanation
Likelihood is medium and conditioned on deployment topology: it only manifests when a single Shipit instance is configured with `github:` keyed by **multiple** organizations (an explicitly documented and supported setup — see `docs/setup.md` "Using Multiple Github Applications" and `test/dummy/config/secrets_double_github_app.yml`). Any actor who is a legitimate webhook sender for one of those configured orgs (i.e., can produce a valid signature for that org's secret) can immediately exploit this without needing a Shipit session, API token, or the other org's secret.

### Recommendation
After `verify_webhook_signature` succeeds for `repository_owner`, re-validate that every organization/owner field the handler will act on (`repository.full_name`'s owner segment, and any commit/stack lookup) matches the same `repository_owner` that authenticated the request. Reject the webhook (422) if these do not match, e.g. by deriving the owner used for `Repository.from_github_repo_name`/`Commit` lookups strictly from the already-authenticated organization rather than trusting the raw payload again.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgOne` and `OrgTwo`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As an actor who legitimately knows/controls `OrgTwo`'s `webhook_secret` (e.g., configured its own GitHub App webhook), craft a `status` event payload:
```json
{
  "sha": "<commit sha belonging to a stack under OrgOne>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgTwo" }, "full_name": "OrgOne/victim-repo" }
}
```
3. Compute `X-Hub-Signature` as `sha1=HMAC_SHA1(OrgTwo_webhook_secret, raw_body)` and POST to `/github/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "OrgTwo")` and successfully validates the signature against `OrgTwo`'s secret.
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — which is a commit under `OrgOne`'s repository — and calls `commit.create_status_from_github!(params)`, creating/forging a CI status for `OrgOne`'s commit despite the request only ever being authenticated for `OrgTwo`.

### Citations

**File:** lib/shipit.rb (L170-181)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
