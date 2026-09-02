### Title
Webhook signature is verified against the org selected from an unverified field, but events are applied to a repository taken from a different unverified field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App / `webhook_secret` used to check the HMAC signature based on `repository_owner`, a value read directly out of the untrusted JSON body. The actual event handlers, however, resolve the target `Stack`/`Repository` from a completely different field of the same untrusted body: `repository.full_name`. Nothing binds these two fields together, so a signature that is valid for organization A does not guarantee that the mutating action performed is actually about a repository belonging to organization A.

### Finding Description
`verify_signature` computes the organization used for secret lookup like this: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — entirely attacker-supplied JSON content, not authenticated in any way before being used to select which `webhook_secret` to verify against. Shipit explicitly supports multiple, independently-secreted GitHub Apps, one per organization: [3](#0-2) 

Once `verify_webhook_signature` passes for whichever org was picked, `create` hands the *entire* raw payload to the event handlers unmodified: [4](#0-3) 

Every handler resolves the `Stack`/`Repository` it acts on from `payload.dig('repository', 'full_name')`, a field independent of `repository_owner`: [5](#0-4) 

Concrete mutating handlers built on this base class then act on whatever `stacks`/`repository` this resolves to, e.g. `PushHandler#process` triggers `sync_github`, `StatusHandler#process` writes a commit CI status, `CheckSuiteHandler#process` schedules check-run refresh, and `PullRequest::ClosedHandler#process` archives a review stack: [6](#0-5) [7](#0-6) [8](#0-7) 

**The broken binding:** "organization that authenticated" (`repository_owner` used to select the HMAC secret) ≠ "repository that is written" (`repository.full_name` used by every handler to select the target `Stack`). An attacker who legitimately controls (or has been given) the webhook secret for *any one* organization configured on the Shipit instance can set `repository.owner.login` / `organization.login` to that organization (so the signature check passes with a secret they know) while setting `repository.full_name` to any other repository/organization's full name that has a `Stack` configured in the same Shipit instance. The signature check has no relationship to the repository actually acted upon.

### Impact Explanation
This is a cross-tenant confused-deputy in a multi-org Shipit deployment: possession of one organization's webhook secret lets an attacker forge webhook events (push, status, check_suite, pull_request, etc.) that are applied to stacks/repositories belonging to a *different* organization that the attacker has no relationship with. Concretely:
- `StatusHandler` lets the attacker write arbitrary CI `state`/`context` for any commit sha in the victim stack's history — this is exactly the "CI status" signal Shipit's `ci.require` / commit-status gating and continuous delivery rely on to decide whether a deploy is safe to trigger, so it can be used to fake successful CI status and unblock/trigger an unauthorized deploy path for a repository/organization the attacker doesn't control.
- `PushHandler`/`CheckSuiteHandler` force stacks belonging to another org to re-sync/refresh state.
- `PullRequest::ClosedHandler` can archive another org's review stacks.

This is a cross-organization write performed without the actual target organization's webhook secret, satisfying the "cross-repository writes / unauthorized deploy" bar, though it requires the multi-organization GitHub App configuration to be in use (single-org deployments have only one secret, so this specific cross-tenant angle collapses to a non-issue there).

### Likelihood Explanation
Requires: (1) the Shipit instance to be configured with multiple GitHub Apps for multiple organizations (a documented, supported configuration — see `docs/setup.md` "Using Multiple Github Applications" and `test/dummy/config/secrets_double_github_app.yml`), and (2) the attacker to know/control one organization's `webhook_secret` (e.g., they administer that org's GitHub App or have a stack in that org and can trigger its webhook delivery, or the secret leaked). Given that, forging the cross-org request is trivial (just crafting a JSON body and HMAC with a known key) and requires no session, no `ApiClient` token, and no access to the victim organization's credentials — it only needs a webhook credential the attacker is entitled to for their own tenant.

### Recommendation
Bind the field used to select the verifying secret to the field used to select the acted-upon repository: verify the signature using every configured organization/App that could plausibly own `repository.full_name`'s owner (not an unrelated `repository_owner` derived independently), or, simpler, derive both from the same authenticated value: after verifying the signature succeeds against the app for `repository_owner`, re-validate that `payload.dig('repository','full_name')`'s owner matches `repository_owner` before dispatching to handlers, rejecting the request otherwise.

### Proof of Concept
1. Deploy Shipit with two configured GitHub orgs, `OrgA` (attacker controls/knows `webhook_secret_A`) and `OrgB` (has a `Stack` for `OrgB/victim-repo`, secret unknown to attacker).
2. Attacker crafts a `status` webhook payload:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required",
  "repository": {"full_name": "OrgB/victim-repo", "owner": {"login": "OrgA"}}
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_A, raw_body)>` and sends `POST /webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: 'OrgA')` (from `repository.owner.login`), verifies successfully against `webhook_secret_A`.
5. `create` dispatches the full payload to `StatusHandler`, which resolves the commit purely by `sha` (global, not scoped to org) and records a fabricated `success` status on `OrgB/victim-repo`'s commit, independent of which org's secret authenticated the request.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
