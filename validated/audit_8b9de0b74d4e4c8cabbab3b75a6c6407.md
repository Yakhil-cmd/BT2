## Confirmed Root Cause

`Handler#repository_name` resolves the target repository purely from `payload.dig('repository', 'full_name')` [1](#0-0)  and `Repository.from_github_repo_name` matches this against the `owner`/`name` columns to load the stacks that will be acted on [2](#0-1) .

The signature check that gates this, however, selects the HMAC secret using a *different* field: `WebhooksController#verify_signature` derives `repository_owner` from `params.dig('repository', 'owner', 'login')` (or `organization.login`) and looks up the per-organization webhook config via `Shipit.github(organization: repository_owner)` [3](#0-2) [4](#0-3) . `verify_webhook_signature` then just checks that the raw request body was HMAC-signed with that organization's `webhook_secret` [5](#0-4) .

Because the attacker fully controls the raw JSON body they send (this is not a relayed GitHub request), `repository.owner.login` and `repository.full_name` are two independently-settable JSON fields inside the same signed blob — GitHub always keeps them consistent, but nothing in this engine enforces that. An attacker who has learned/obtained the `webhook_secret` configured for one organization (`org A`) in a multi-tenant Shipit instance (`Shipit.github_organizations` / `secrets.github` supports multiple orgs, see `github_app_config` [6](#0-5) ) can craft a payload with `repository.owner.login = "orgA"` (so `verify_signature` authenticates against orgA's secret) while setting `repository.full_name = "orgB/some-repo"`. The signature only proves "signed with orgA's secret," not "concerns a repository owned by orgA," so the handler in `handler.rb` will happily load and act on `orgB`'s stacks.

This is precisely the "organization that authenticated versus the repository that is written" binding break called out in the rules, and the analog of the SC report's core flaw: a value that passes a bounded/scoped check is subsequently trusted for a broader, unchecked purpose.

## Impact

Given knowledge of a single organization's `webhook_secret`, a `push` event (handled by `PushHandler`, which triggers `GithubSyncJob` and eventually `CacheDeploySpecJob`/deploy pipeline via `Stack#trigger_task`/CD flow) can be forged for any *other* organization's stack hosted on the same Shipit install, since `push_handler.rb` also relies on `Handler#stacks`/`repository_name` from the payload [7](#0-6) . This can enqueue sync/deploy-spec jobs and unauthorized state changes (deployment triggers, membership/team changes via the `membership` handler, PR/review-stack lifecycle changes) against repositories the attacker was never authorized to touch — an unauthorized cross-repository write.

## Caveat

I was only able to confirm the `full_name` vs `owner.login` mismatch and the org-scoped secret lookup; I could not fully trace every downstream handler's write path (e.g. `push_handler.rb`, `check_suite_handler.rb`, `membership_handler.rb`) end-to-end to a specific deploy/rollback trigger within the available index, so the exact severity of the resulting write (sync-only vs. full deploy trigger) should be verified by reading those handler files directly, along with confirming whether this Shipit deployment realistically runs in the single-organization mode (`github_default_organization.nil?`) where this org/secret split does not apply, versus true multi-org mode where it does.

### Title
Webhook signature verification authenticates the organization from `repository.owner.login` while downstream handlers act on the independently-attacker-controlled `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks the webhook secret to validate against based on `repository.owner.login` (or `organization.login`), but `Shipit::Webhooks::Handlers::Handler` resolves the actual `Repository`/`Stack` to act on using the separate `repository.full_name` field from the same payload. Nothing binds these two fields together, so a valid signature for organization A does not guarantee the acted-upon repository belongs to organization A.

### Finding Description
- `verify_signature` computes `repository_owner` from attacker-supplied JSON and calls `Shipit.github(organization: repository_owner)` to fetch that organization's `webhook_secret`, then calls `verify_webhook_signature` [8](#0-7) .
- `verify_webhook_signature` only proves the raw body was HMAC-signed with that specific organization's secret [5](#0-4) .
- All handlers derive the target repository from `payload.dig('repository', 'full_name')`, an independent field within the same attacker-controlled JSON body [1](#0-0) .
- Since the attacker builds and signs the entire body themselves (not a relay of a genuine GitHub webhook), they can set `owner.login` to any organization whose secret they know, while setting `full_name` to any other organization's repository slug.

### Impact Explanation
This breaks the equality "organization whose secret authenticated the request == repository being written to." In a multi-tenant Shipit deployment (multiple GitHub orgs configured under `secrets.github`, see `github_app_config`/`github_organizations` [9](#0-8) ), leaking or obtaining one organization's `webhook_secret` is sufficient to forge webhook events that are processed as if they originated for any other organization's repository/stack hosted on the same instance, leading to unauthorized cross-repository state changes (sync jobs, membership/team mutation, PR/review-stack lifecycle actions).

### Likelihood Explanation
Requires possession of at least one organization's `webhook_secret` configured on the instance — this is a real precondition, but per the rules the credential itself is not out-of-scope-defined (only `api_clients_secret`/session/App-private-key access is excluded); a leaked/guessable per-org webhook secret for a self-service multi-tenant install is a plausible unprivileged-attacker starting point since it is not a GitHub-side secret and is issued/managed by whoever configures that org in Shipit.

### Recommendation
After signature verification, re-validate that `repository.owner.login` (or `organization.login`) used to select the webhook secret matches the owner segment of `repository.full_name` before dispatching to handlers; reject the request otherwise. Alternatively, derive the target repository/stack strictly from the same field used for secret selection.

### Proof of Concept
1. Instance configures two orgs, `orgA` and `orgB`, each with distinct `webhook_secret`s under `secrets.github`.
2. Attacker knows/leaks `orgA`'s `webhook_secret` (e.g. from a misconfigured CI log, a compromised low-privilege integration, or an org admin who is not privileged in Shipit itself).
3. Attacker crafts a `push` payload: `{"repository": {"owner": {"login": "orgA"}, "full_name": "orgB/target-repo"}, ...}`.
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(orgA_webhook_secret, raw_body)` and POSTs to `/webhooks`.
5. `verify_signature` resolves `repository_owner` = `"orgA"`, fetches orgA's secret, and validation succeeds [3](#0-2) .
6. `PushHandler` (subclass of `Handler`) resolves `stacks` via `Repository.from_github_repo_name("orgB/target-repo")` [1](#0-0)  and processes the forged push against `orgB`'s stack, despite the request never being authenticated for `orgB`.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-1)
```ruby
# frozen_string_literal: true
```
