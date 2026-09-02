### Title
Cross-organization job scheduling via mismatched webhook-signing org vs. `repository.full_name` in check_suite handling - ([File: app/models/shipit/webhooks/handlers/check_suite_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using `repository_owner` (`payload.dig('repository','owner','login')` or `organization.login`), but `Handler#repository_name`, used by `CheckSuiteHandler#process` to resolve the target `Repository`/`stacks`, reads the independent `payload.dig('repository','full_name')` field. Nothing ties these two fields together, so a payload validly signed for organization A can carry a `repository.full_name` pointing at organization B's repository.

### Finding Description
The binding this endpoint should enforce is: `organization_that_signed(payload) == organization_owning(repository.full_name)`, i.e. `repository_owner(payload) == repository.full_name.split('/').first`. Nothing in the code enforces this equality.

- `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and verifies `X-Hub-Signature` against that org's configured `webhook_secret` [1](#0-0) , where `repository_owner` is `payload.dig('repository','owner','login') || payload.dig('organization','login')` [2](#0-1) .
- `Handler#repository_name`, used by `CheckSuiteHandler#process` via the shared `stacks` helper, reads a **different** JSON key, `payload.dig('repository','full_name')`, with no cross-check against `repository.owner.login`: [3](#0-2) .
- `CheckSuiteHandler#process` only validates `check_suite.head_sha`/`check_suite.head_branch` via `ExplicitParameters`, not `repository`, and then does `stacks.where(branch: params.check_suite.head_branch).each { |stack| stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!) }` [4](#0-3) .
- Which secret is used for verification depends on `Shipit.github`, which supports per-organization `webhook_secret` config keyed by org login (`github_app_config`) in multi-tenant deployments: [5](#0-4) .

Exploit flow (multi-org Shipit deployment, i.e. `secrets.github` keyed by organization, each org having its own `webhook_secret`): an attacker who administers organization "OrgA" (and therefore legitimately knows OrgA's own webhook secret, since they configured that GitHub App installation) crafts a `check_suite` payload with `repository.owner.login = "OrgA"` (so the controller verifies the HMAC using OrgA's own secret, which succeeds) but `repository.full_name = "OrgB/victim-repo"` and attacker-chosen `check_suite.head_sha`/`head_branch`. `verify_signature` passes because the signature is valid for OrgA. `CheckSuiteHandler#process` then resolves `Repository.from_github_repo_name("OrgB/victim-repo")` — a repository belonging to a different, unrelated tenant — and enqueues `RefreshCheckRunsJob` against victim's stack/commit with the attacker-supplied sha, causing Shipit to make GitHub API calls against the victim's real repository using the app's install credentials.

None of the existing guards prevent this: `verify_signature` only checks the HMAC against the org derived from `repository.owner.login`, not that this org matches `repository.full_name`'s owner; `drop_unhandled_event` and `ExplicitParameters` schema for `CheckSuiteHandler` don't require or validate a `repository` block at all; and `stacks`/`Repository.from_github_repo_name` performs no tenant-scoping — it matches on `owner`+`name` across the entire Shipit installation.

### Impact Explanation
A tenant of a multi-org Shipit installation can force job scheduling (`RefreshCheckRunsJob`) against a completely different tenant's stack/commit with attacker-chosen `head_sha`, causing Shipit's install credentials to be used to query GitHub's Checks API on the victim's repository for an arbitrary, attacker-supplied SHA. This is a payload authenticated for one repository/organization mutating another's stack/commit state, matching the Critical impact category ("a payload for one repository mutating another's stack, commit, task or team"). It is fully repeatable against any repository/stack tracked by the same Shipit installation, for every `check_suite` webhook the attacker chooses to send, and generalizes to other handlers built on `Handler#repository_name` (e.g., pull_request handlers) wherever the schema doesn't independently bind `repository.full_name`'s owner to the signing org.

### Likelihood Explanation
This requires a multi-org Shipit deployment where `secrets.github` is keyed per-organization (each tenant organization has its own GitHub App/installation and its own `webhook_secret`), which is a supported and documented configuration path (`github_app_config`, `github_organizations`). In that configuration, any onboarded tenant admin — who legitimately knows only their own org's webhook secret and has no access to any Shipit session, API token, or victim's secrets — can trivially construct and POST a JSON payload to `/webhooks` with a valid signature for their own org while spoofing `repository.full_name` to name any other tracked repository. Cost is a single crafted HTTP POST; no GitHub-side action (PR, push) is even required since the webhook endpoint accepts raw POSTs directly. In a single-tenant (legacy top-level `github:` config) deployment this specific cross-org exploit does not apply, since `repository_owner` is ignored entirely and a single global secret is used for all repos, but this does not mitigate the flaw in supported multi-tenant configurations.

### Recommendation
In `Handler#repository_name` (or in each handler's schema/`process`), require and validate that `payload.dig('repository','owner','login')` (or `organization.login`) equals the owner portion of `payload.dig('repository','full_name')`, rejecting the event (or falling back to the owner login exclusively) if they diverge. More robustly, `WebhooksController` should pass the already-verified `repository_owner` down to handlers and have `stacks`/`Repository.from_github_repo_name` scope lookups to that verified owner instead of trusting the unauthenticated `full_name` field for tenant resolution.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or a new `check_suite_handler_test.rb`):
1. Stub `Shipit.github` to return per-organization configs: `Shipit.github(organization: 'OrgA')` with secret `"secretA"`, and ensure a `Repository`/`Stack`/`Commit` fixture exists for `owner: "orgb", name: "victim-repo"` with `branch: "main"`.
2. Build a `check_suite` JSON payload: `repository.owner.login = "OrgA"`, `repository.full_name = "OrgB/victim-repo"`, `check_suite.head_branch = "main"`, `check_suite.head_sha = <victim commit sha>`.
3. Compute `X-Hub-Signature` as `"sha1=" + OpenSSL::HMAC.hexdigest('sha1', "secretA", raw_body)`.
4. Assert both sides of the binding: `repository_owner(payload) == "OrgA"` (the signing org) while `payload.dig('repository','full_name').split('/').first.casecmp("OrgA") != 0` (i.e. `"OrgB" != "OrgA"`).
5. POST to `/webhooks` with `X-Github-Event: check_suite` and the computed signature; assert `response.status == 200`.
6. `assert_enqueued_with(job: RefreshCheckRunsJob, args: [stack_id: victim_stack.id, sha: victim_commit.sha])`, proving the OrgA-signed payload scheduled a job against OrgB's stack/commit despite the mismatched owning organizations.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L7-17)
```ruby
        params do
          requires :check_suite do
            requires :head_sha, String
            requires :head_branch, String
          end
        end
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
