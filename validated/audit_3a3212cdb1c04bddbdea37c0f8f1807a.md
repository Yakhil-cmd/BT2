## Analysis

This confirms the analog vulnerability: `Shipit.github(organization:)` supports per-organization webhook secrets keyed by an organization name, but the webhook signature is verified using the secret for `repository_owner` (attacker-supplied via `params.dig('repository','owner','login')` or `params.dig('organization','login')`), while the actual repository acted upon by handlers is `payload.dig('repository','full_name')` — an independent, unverified field. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Title
Webhook signature verification uses attacker-controlled `repository.owner.login` to select the secret, allowing cross-organization repository writes - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against by reading `repository_owner`, a field taken directly from the unauthenticated JSON body, not from any verified/authenticated channel. `Handler#repository_name` (and thus which `Stack`/`Repository` is mutated) is read from a *different* field of the same unauthenticated body (`repository.full_name`). Because these two fields are never bound together by the signature, an attacker who knows or controls the webhook secret for **any one** configured organization can forge a payload whose `repository.owner.login` matches that known organization (satisfying signature verification) while `repository.full_name` names a repository belonging to a **different** organization/stack, causing Shipit to sync, deploy-trigger, or otherwise act on that unrelated repository.

### Finding Description
In a multi-org Shipit deployment, `Shipit.github(organization:)` looks up a distinct `webhook_secret` per organization via `github_app_config(organization)`. [1](#0-0) 

`WebhooksController#verify_signature` computes which organization's secret to use purely from the request body:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

and then verifies `X-Hub-Signature` against `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [5](#0-4) 

However, the handlers that act on the payload (e.g. `PushHandler`) resolve the target `Stack` via `Repository.from_github_repo_name(repository_name)`, where `repository_name = payload.dig('repository', 'full_name')` — a separate field from `repository.owner.login`. [4](#0-3) [6](#0-5) 

Nothing in the signature computation binds `owner.login` to `full_name`: the raw request body is HMAC-signed as a whole by GitHub for the org that actually sent it, but Shipit's *choice of which secret to check against* is derived from an attacker-writable field of that same body, and the field that determines the operated-on repository is a **different** attacker-writable field. This is the same class of bug as the report's `executeSwap`/`executeSwapDirect` mismatch: the value used to authorize the action (`caller`/`organization`) is not the value the action actually executes against (`token`/`repository.full_name`). An attacker who has a legitimate GitHub webhook secret for org `A` (e.g., because they administer a repo under org `A` in the same Shipit instance) can craft a POST with:
- `X-Hub-Signature`: valid HMAC over the body using org `A`'s secret
- `repository.owner.login`: `"A"` (so `verify_signature` picks org `A`'s secret and passes)
- `repository.full_name`: `"B/some-repo"` (a repository actually configured under a different org `B` in the same Shipit instance)

`verify_signature` succeeds because it only checks the org named in `owner.login`, and the handler then acts on `B/some-repo` using data controlled by the attacker (e.g., `after` SHA for `PushHandler`, triggering `GithubSyncJob`, or `status`/`check_suite` state transitions) — a cross-organization write that should have required org `B`'s secret.

### Impact Explanation
This breaks the binding "organization that authenticated == repository that is written," letting an attacker with only one org's webhook secret forge sync/status/check-run events for repositories belonging to a different organization hosted on the same Shipit instance, causing unauthorized state changes (e.g., forcing `GithubSyncJob` enqueues, faking commit statuses/check runs that influence deploy eligibility) on repos they do not control. This matches the "cross-repository writes" / "unauthorized deploy" impact bucket, since faked `status`/`check_suite` events can flip `deployable_status`/`merge_status` used to gate deploys.

### Likelihood Explanation
Requires the attacker to already hold a webhook secret for **some** organization configured in the same Shipit instance (plausible in multi-tenant Shipit deployments where different teams manage different GitHub orgs behind one Shipit install) and knowledge of a target repository's `full_name` in another org, which is not secret. No GitHub App private key, session, or API token is needed — only a per-org webhook secret, which is a weaker credential than the ones this engine's admins typically consider sensitive across-org.

### Recommendation
Bind organization identity to the acted-upon repository: after verifying `repository_owner` for HMAC purposes, additionally verify that `payload.dig('repository','full_name')` actually belongs to that same organization (e.g., `full_name.split('/').first.casecmp?(repository_owner)`) before dispatching to handlers, or reject the payload otherwise.

### Proof of Concept
1. Configure Shipit with two orgs, `A` and `B`, each with its own `github.webhook_secret` (multi-org schema in `secrets.github`).
2. Attacker has org `A`'s webhook secret (e.g., is a maintainer with access to org `A`'s GitHub App settings).
3. Attacker crafts body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": { "owner": { "login": "A" }, "full_name": "B/some-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(body, orgA_webhook_secret)>` and sets `X-Github-Event: push`.
5. `WebhooksController#verify_signature` computes `repository_owner == "A"`, loads org `A`'s app/secret, verifies signature successfully.
6. `PushHandler#process` resolves `Repository.from_github_repo_name("B/some-repo")` and enqueues `GithubSyncJob` for stacks under org `B`, despite the attacker never possessing org `B`'s webhook secret. [7](#0-6) [8](#0-7) [6](#0-5)

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
