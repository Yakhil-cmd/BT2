### Title
Webhook signature verification is keyed to an attacker-controlled `repository.owner.login`, but downstream handlers act on a separately attacker-controlled `repository.full_name` / `organization.login` — allowing cross-organization writes with a self-signed webhook - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
### Finding Description
This is the same trust-binding-mismatch bug class as the report: a field is verified/authenticated, while a *different* field taken from the same untrusted payload is the one actually acted upon, with no equality check between the two.

`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC signature against using a value pulled directly out of the unauthenticated JSON body: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up a per-organization `webhook_secret` from `secrets.github` in multi-org deployments [2](#0-1) , and `verify_webhook_signature` simply HMACs the raw body with that org's secret [3](#0-2) .

Once the signature is accepted, the actual event processing does not use `repository.owner.login` again — it uses `repository.full_name` (or the `organization`/`team`/`member` sub-objects, depending on handler) to resolve which `Stack`/`Repository`/`Team` to mutate: [4](#0-3) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

Because the attacker fully controls the JSON body of their own webhook request (only the `X-Hub-Signature` header must match the secret for whichever organization they name in `repository.owner.login`), nothing prevents `repository.owner.login` (used for signature-secret selection) from disagreeing with `repository.full_name` or `organization.login` (used for the actual database write). The binding that should hold — "the organization whose secret authenticated this request" == "the organization/repository whose Shipit state is mutated" — is never checked.

### Impact Explanation
An attacker who legitimately controls a GitHub organization that has the Shipit GitHub App installed (a routine, self-service action requiring no privileged access to the target Shipit deployment or the victim organization) knows that organization's `webhook_secret`. They can:
1. Sign a webhook payload with their own org's secret (`repository.owner.login = "attacker-org"`).
2. Set `repository.full_name` (for `push`/`status`/`check_suite` handlers) or `organization.login`/`team`/`member` (for the `membership` handler) to point at a victim's repository/team.
3. POST it to `/webhooks`.

`verify_signature` succeeds because it only checks the signature against attacker-org's secret. The event is then dispatched to handlers that operate on the victim stack/team using the forged field:
- `push` → enqueues `GithubSyncJob`/triggers sync for a stack the attacker doesn't own.
- `status`/`check_suite` → forges CI status/check results for a victim's commits, which downstream is a trust input feeding `deployable?`/CI gating decisions used before triggering a deploy.
- `membership` → creates/deletes `Team`/`Membership` records for an arbitrary GitHub org/team, directly manipulating `Shipit.github_teams`-based authorization (`User#authorized?`), which is an explicit High-impact category in scope ("escalation into `Shipit.github_teams` authorization").

This crosses the organization/repository trust boundary defined by the multi-app webhook design and can escalate into unauthorized CI-status forgery and authorization-group tampering without any Shipit session, API token, or victim-org credential.

### Likelihood Explanation
Requires only that the attacker control (or create) any GitHub organization with the Shipit GitHub App installed — a self-service, unprivileged setup step available to any GitHub user in installations that use the "Using Multiple GitHub Applications" mode documented in `docs/setup.md`. No access to the victim's secrets, tokens, or GitHub org is needed. The webhook endpoint is unauthenticated aside from the per-org HMAC.

### Recommendation
After verifying the signature, cross-check that `repository_owner` (the field used to select the verifying app/secret) matches the owner embedded in `repository.full_name` (and, for the `membership` event, that `organization.login` equals `repository_owner`/the app being used) before dispatching to handlers. Reject the webhook if these disagree.

### Proof of Concept
1. Configure Shipit with two GitHub Apps under `secrets.github`: `attacker-org` (secret `S1`, installed by the attacker on their own GitHub org) and `victim-org` (secret `S2`, unknown to the attacker), matching the multi-org config in `docs/setup.md#using-multiple-github-applications`.
2. Craft a `push` (or `membership`) webhook JSON body with `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"` (or, for `membership`, `organization.login = "victim-org"`).
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(S1, raw_body)>` using the known `attacker-org` secret.
4. POST to `/webhooks` with headers `X-Github-Event: push` (or `membership`) and the computed signature.
5. Observe `verify_signature` passes (it only checked against `attacker-org`'s secret) and `Shipit::Webhooks.for_event(event)` handlers execute against `victim-org/victim-repo`'s stacks (e.g., `GithubSyncJob` enqueued, or a `Team`/`Membership` created/deleted for `victim-org`), confirming the cross-organization write.

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
