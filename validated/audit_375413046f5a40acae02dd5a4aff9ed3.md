### Title
Cross-organization webhook forgery breaks the "authenticated organization = written repository" binding - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the request signature against based on `repository.owner.login` (or `organization.login`) taken directly from the attacker-controlled JSON body, before that body is trusted. The event handlers that actually act on the payload (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`) never re-check that field — they resolve the target `Stack`/`Commit` using `repository.full_name` (`Handler#repository_name`) or bare `sha`/`branch` fields. Because nothing enforces that `repository.owner.login` matches `repository.full_name`'s owner segment, an attacker who legitimately administers *their own* onboarded GitHub organization (and therefore knows *its* `webhook_secret`, per the documented "Using Multiple GitHub Applications" multi-tenant setup) can sign an arbitrary payload with their own secret while setting `repository.full_name` to point at a victim org/repo tracked by the same Shipit instance.

### Finding Description
`Shipit::WebhooksController#verify_signature` does: [1](#0-0) 
which calls `repository_owner`: [2](#0-1) 

`Shipit.github(organization:)` maps the organization name to a per-org `webhook_secret` configured in `secrets.github`: [3](#0-2) 

The HMAC check itself (`GitHubApp#verify_webhook_signature`) is correct as an HMAC — it proves the whole raw body was signed with *some* known secret: [4](#0-3) 

However, once verification passes, the event `params` (the same attacker-controlled JSON) are dispatched to handlers that resolve the *target* repository/stack from a **different** field — `repository.full_name` — never cross-checked against `repository.owner.login` used for secret selection: [5](#0-4) 

Concrete handlers that act on this mismatched binding: [6](#0-5) [7](#0-6) [8](#0-7) 

The broken equality is: **organization whose secret authenticated the signature == organization/repository the payload actually writes to**. `repository_owner` (used to pick the verifying secret) is read from `repository.owner.login`, while every handler's actual target lookup uses `repository.full_name` (`Handler#repository_name`) or bare commit `sha`. Nothing enforces `full_name.split('/').first == owner.login`, so these two fields can diverge in an attacker-crafted body while the signature still validates.

This configuration is explicitly supported/documented ("Using Multiple Github Applications", `docs/setup.md`), so a single Shipit deployment can host several independently-administered GitHub orgs, each with its own `webhook_secret` known to that org's own administrators — exactly the "unprivileged relative to the victim" attacker this scan requires.

### Impact Explanation
An attacker who administers their own onboarded org (Org A, knows Org A's `webhook_secret`, but has no access/permissions on victim Org B's repository) can forge a signed webhook whose `repository.owner.login` = "OrgA" (to pass signature verification) but whose `repository.full_name` = "OrgB/victim-repo" (to target the victim stack). This lets the attacker:
- Forge a GitHub commit `status` for an arbitrary existing commit SHA in the victim's tracked stack via `StatusHandler#process` → `Commit#create_status_from_github!`, marking a required CI context as `success` for a commit that never actually passed CI — directly subverting the `ci.require`/blocking-status gate that governs whether continuous delivery is allowed to deploy that commit.
- Trigger `PushHandler#process` → `stack.sync_github` and `CheckSuiteHandler#process` → `schedule_refresh_check_runs!` against the victim stack using data attributable to Org A's authenticated session.

Forging a passing CI status to unblock an otherwise-blocked deploy is an unauthorized-deploy-enabling primitive, matching the "unauthorized deploy" High/Critical impact category.

### Likelihood Explanation
Requires the attacker to control (or be an admin of) at least one GitHub organization/App already configured in the same multi-tenant Shipit instance (per the documented multi-org secrets format) — a realistic scenario for any shared/SaaS-style Shipit deployment onboarding multiple independent orgs — and requires the victim stack to have a commit whose SHA the attacker can predict/observe (trivially, from the victim's public/known git history). No access to the victim's `webhook_secret`, `GITHUB_TOKEN`, or Shipit session is needed.

### Recommendation
In `Handler#repository_name` (or `WebhooksController`), verify that the `repository.full_name` owner segment matches the organization whose secret validated the signature (`repository_owner`), and reject the webhook otherwise. Alternatively, derive the verifying organization strictly from `repository.full_name`'s owner segment rather than from the separate `repository.owner.login`/`organization.login` field, so a single field drives both secret selection and target resolution.

### Proof of Concept
1. Attacker administers Org A in a multi-org Shipit deployment and knows Org A's `webhook_secret` (as documented in "Using Multiple Github Applications").
2. Attacker crafts a JSON body:
```json
{
  "sha": "<victim-commit-sha-that-exists-in-OrgB/victim-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "full_name": "OrgB/victim-repo", "owner": { "login": "OrgA" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_OrgA, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates successfully.
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which resolves the target via `Commit.where(sha: params.sha)` — matching the real victim commit in `OrgB/victim-repo` — and calls `commit.create_status_from_github!(params)`, forging a `success` status for a required CI context the attacker never actually ran, on a repository the attacker has no access to.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
