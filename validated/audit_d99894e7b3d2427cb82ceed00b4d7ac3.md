### Title
Webhook signature is verified against the org derived from `repository.owner.login`, while the repository actually acted upon is derived from the independent `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/org secret to validate the HMAC with based on `params.dig('repository','owner','login')` (or `organization.login`), while every event handler (`PushHandler`, `CheckSuiteHandler`, `Handler#repository_name`/`#stacks`, etc.) resolves the repository/stack to act on from the independent `repository.full_name` field of the same attacker-suppliable JSON body. Because Shipit supports multiple GitHub Apps/organizations each with its own `webhook_secret` [1](#0-0) , a signature that is valid for org A says nothing about the `repository.full_name` value also embedded in the same payload, since these are two different sub-fields (`repository.owner.login` vs `repository.full_name`) that the controller and handler read independently.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and uses it purely to select the signing config: [2](#0-1) [3](#0-2) 

`Shipit.github(organization:)` looks up the per-organization app config (and its own `webhook_secret`) from `secrets.github`, supporting exactly the "Using Multiple Github Applications" scheme documented in `docs/setup.md` [4](#0-3) , and `verify_webhook_signature` HMACs the *entire raw body* with that org's secret [5](#0-4) .

Handlers never re-check that the signed `repository.owner.login` matches the `repository.full_name` used to find the target repository/stack. `Handler#repository_name` and `#stacks` use `payload.dig('repository', 'full_name')` directly: [6](#0-5) 

`PushHandler` and `CheckSuiteHandler` then act on those stacks (triggering a GitHub sync / commit-status refresh) using only `branch`/`sha` matching, with no repository ownership re-validation: [7](#0-6) [8](#0-7) 

The binding that is expected to hold is: `organization whose secret validated the HMAC == owner of the repository the handler mutates`. In practice the controller/handlers evaluate this as `repository.owner.login (used for signature selection) == repository.full_name's owner (used for the actual stack lookup)`, but nothing enforces these two independently-read fields are consistent within the same JSON body, because the HMAC only proves "some byte sequence was signed by org A's secret" — not "the semantic fields inside it are internally consistent."

An attacker who legitimately administers a GitHub App/organization "OrgA" in a multi-org Shipit deployment (and therefore legitimately knows OrgA's `webhook_secret`, which they configured themselves when installing their own app) can craft a JSON payload where `repository.owner.login` = `"OrgA"` (so the controller picks OrgA's secret and the HMAC validates), but `repository.full_name` = `"OrgB/victim-repo"` (a repository/stack belonging to a different, unrelated organization tracked by the same Shipit instance). The webhook is accepted, and the handler acts on `OrgB/victim-repo`'s stacks using data the attacker fully controls (branch names, SHAs, commit statuses, check-suite refresh triggers), even though the attacker has no access to OrgB whatsoever.

### Impact Explanation
Because `push`/`status`/`check_suite`/`membership` events act on whatever `repository.full_name` (or `organization.login` for membership) is present, this crosses a genuine authentication boundary: an actor who is only authorized (owns a webhook secret) for org A can push fabricated events that are processed as if they came from org B's repository. Concretely: `PushHandler` calls `stack.sync_github(expected_head_sha:)` for an attacker-chosen SHA/branch on a foreign stack, and `StatusHandler`/`CheckSuiteHandler` let an attacker inject arbitrary commit statuses / trigger check-run refresh scheduling for commits in a foreign stack. Depending on downstream trust of these statuses in `merge_request` / `continuous_delivery` gating (`all_status_checks_passed?`, `reject_unless_mergeable!`), a forged "success" status from `status` events could help push a merge queue past a required CI gate on a repo the attacker does not own — an unauthorized cross-repository write / deploy-trust bypass consistent with the "Critical: cross-repository writes / unauthorized deploy" impact category.

### Likelihood Explanation
This requires the Shipit instance to be configured for multiple GitHub organizations (the documented "Using Multiple Github Applications" mode) and for the attacker to be a legitimate, unprivileged administrator of at least one of those organizations/apps (so they know that org's `webhook_secret`) while also being unprivileged with respect to the target org/repo. This is a realistic multi-tenant configuration this engine explicitly supports, and no additional GitHub write access, Shipit session, or `ApiClient` token is required — only the ability to send an HTTP POST to `/webhooks` with a JSON body crafted so its `repository.owner.login`/`organization.login` differs from its `repository.full_name`.

### Recommendation
After signature verification, re-derive the repository/organization strictly from the same field(s) used to select the verification secret, and reject the request (or ignore repository resolution from a different field) if `repository.full_name`'s owner does not match `repository.owner.login`/`organization.login` used to choose the app. Alternatively, verify the payload's HMAC using the app config resolved from `repository.full_name`'s owner segment directly, so a single canonical field drives both which secret is used and which repository is acted upon.

### Proof of Concept
1. Configure Shipit with two GitHub Apps/orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org config) [1](#0-0) .
2. As the legitimate admin of `OrgA`'s GitHub App, obtain `OrgA`'s `webhook_secret` (you set it yourself when installing the app).
3. Build a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
4. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches OrgA's app/secret, and the HMAC validates [9](#0-8) .
6. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("OrgB/victim-repo")` (through `Handler#stacks`) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on `OrgB`'s stack [7](#0-6) [6](#0-5) , despite the attacker having no legitimate relationship to `OrgB`.

Note: I was not able to fully trace how far a forged `status` event's effect propagates into merge-queue gating (`MergeRequest#all_status_checks_passed?`) within the available index, so the "forces a merge" escalation is a plausible but not fully proven downstream consequence — the cross-repository state mutation (triggering syncs/refreshes on a foreign stack) via a mismatched org/repo pair itself is confirmed directly in the cited code.

### Citations

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
