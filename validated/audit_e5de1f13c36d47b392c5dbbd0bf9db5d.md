## Title
Cross-organization webhook forgery via mismatched signature-key selection and repository-write binding - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify a payload against using the *claimed* `repository.owner.login` (or `organization.login`) field from the untrusted JSON body, but the handlers that subsequently act on the payload (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `MembershipHandler`, PR handlers) select the target `Stack`/`Repository` using a *different* field from the same untrusted body — `repository.full_name` (see `Handler#repository_name` and `Handler#stacks`). Nothing ties the two fields together, so the organization whose secret authenticates the request is not necessarily the organization/repository the request is allowed to write to.

### Finding Description
The verification step is: [1](#0-0) 

Key selection is based on `repository_owner`: [2](#0-1) 

But every handler resolves the target stacks from a *separate* field, `repository.full_name`, without cross-checking it against the value used for signature verification: [3](#0-2) [4](#0-3) 

Shipit explicitly supports hosting multiple GitHub organizations behind one instance, each with its own independent `webhook_secret` (`docs/setup.md` "Using Multiple Github Applications", `test/dummy/config/secrets_double_github_app.yml`). `Shipit.github(organization:)` looks the secret up purely by the organization name supplied in the request: [5](#0-4) 

Because `repository_owner` (used to pick the secret) and `repository.full_name` (used to pick the `Repository`/`Stack` to act on) are independent, unvalidated fields of the same attacker-supplied JSON body, an actor who legitimately owns/administers **any one** GitHub organization configured in this Shipit instance (and therefore genuinely knows that organization's `webhook_secret` — a value they can view themselves after installing their own GitHub App) can:
1. Set `repository.owner.login` (or `organization.login`) to their own org name, so `Shipit.github(organization: repository_owner)` resolves to the app config they legitimately control, and sign the raw body with that secret so `verify_signature` passes.
2. Set `repository.full_name` (and other payload fields the handler reads, e.g. `ref`, `after`, `sha`, `state`) to point at a **different** organization/repository tracked by the same Shipit instance.

The signature-verified identity (organization A) and the entity the handler writes to (repository/stack under organization B) are never checked for equality — this is exactly the "verified field vs. acted-upon field" and "organization authenticated vs. repository written" binding described in the report's bug class, reproduced here as: `verify_signature` binds `signature ⇔ Shipit.github(organization: repository_owner).webhook_secret`, while `Handler#stacks` binds `write-target ⇔ Repository.from_github_repo_name(repository.full_name)`, and these two bindings are never required to reference the same organization.

### Impact Explanation
This lets an attacker who controls one tenant/org on a shared Shipit instance forge webhook events attributed to a different tenant's repositories:
- `PushHandler` calls `stack.sync_github(expected_head_sha: ...)` for any not-archived stack on the forged branch — capable of injecting arbitrary/forged commit metadata under `expected_head_sha` and driving `GithubSyncJob` against a repository the attacker does not control, which can register attacker-chosen commits/refs as the "expected" head for another org's deploy pipeline.
- `StatusHandler`/`CheckSuiteHandler` can inject forged CI/check-run states onto another organization's commits, and since `Commit#deployable?` and `Stack#deployable?` gate continuous deployment/deploy eligibility on status/check state (`app/models/shipit/commit.rb` `deployable?`), a forged "success" status on a victim repository's commit can make an otherwise-non-deployable commit `deployable?`, enabling an unauthorized deploy through Shipit's continuous-delivery path once combined with `continuous_deployment`.
- `MembershipHandler` can add/remove `Team`/`Membership` records for users unrelated to the attacker's own org, since it too only relies on unauthenticated body content once the signature check passes.

This crosses the "cross-repository writes" / "unauthorized deploy" bar defined as Critical impact, and requires no session, API token, or GitHub write access to the victim's repository — only that the attacker administers some GitHub organization onboarded to the same shared Shipit deployment.

### Likelihood Explanation
Exploitability depends entirely on Shipit being configured in the documented multi-organization mode (multiple orgs, each with its own `webhook_secret`, sharing one Shipit instance) — a configuration the project explicitly documents and supports. Any attacker who is an admin of one such tenant organization can read their own `webhook_secret` from their GitHub App settings and forge the payload described above with a standard HTTP client; no privileged Shipit credential or access to the victim org is required.

### Recommendation
After signature verification succeeds, bind the verified organization to every subsequent lookup: require that `repository.full_name`'s owner (and `organization.login` if present) exactly matches `repository_owner`/the organization whose secret validated the signature before dispatching to any handler, and have `Handler#stacks`/`Handler#repository_name` reject any payload where the derived repository owner differs from the verified organization.

### Proof of Concept
Conceptual reproduction (cannot be executed without a live multi-org Shipit deployment):
1. Configure Shipit with two organizations, `OrgA` (attacker-controlled, webhook secret `sA`) and `OrgB` (victim, hosting a tracked stack `orgb/app`), per `secrets_double_github_app.yml` style config.
2. As the OrgA admin, obtain `sA` legitimately from the GitHub App settings.
3. Craft a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "orgb/app" }
}
```
4. Compute `X-Hub-Signature: sha1=HMAC-SHA1(sA, raw_body)` and POST to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates successfully against `sA`.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("orgb/app")`, matching the victim's stack, and triggers `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` — a write against OrgB's stack authenticated only by OrgA's secret.

I was not able to fully trace `Stack#sync_github`/`GithubSyncJob` internals or `Commit#deployable?`'s full interaction with continuous deployment in this pass (index size limits truncated some of `app/models/shipit/stack.rb` and job files); a Devin session with full repository access would be needed to confirm the exact downstream consequence (e.g., whether `sync_github` alone can flip a commit to `deployable?` and trigger an actual unauthorized deploy versus only updating cached metadata).

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
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
