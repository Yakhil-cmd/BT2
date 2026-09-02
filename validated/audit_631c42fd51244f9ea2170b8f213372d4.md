## Confirmed vulnerability: cross-organization signature confusion in webhook processing

### Title
Webhook signature verified against attacker-controlled organization while the repository acted upon is taken unchecked from the same payload — cross-tenant unauthorized deploy trigger - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the HMAC signature against by reading `repository.owner.login` (or `organization.login`) directly out of the *same, attacker-supplied* JSON body it is about to validate. The webhook handlers that subsequently act on the payload (e.g. `PushHandler`) resolve the target `Stack`/`Repository` from a *different* field of the same body — `repository.full_name` — without ever re-checking that this repository actually belongs to the organization whose secret validated the signature.

### Finding Description
`verify_signature` computes the trust anchor like this: [1](#0-0) 

`repository_owner` is read straight from the untrusted payload: [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up per-organization config keyed by that string and uses its `webhook_secret` to verify the signature: [3](#0-2) [4](#0-3) 

Once the request passes, the actual repository written to is derived from an *independent* field of the identical payload, with no cross-check against `repository_owner`: [5](#0-4) [6](#0-5) 

**Binding broken (equality that should hold but doesn't):**
`organization whose secret authenticated the request` == `organization owning the repository the handler writes to`.

Before the attacker's request: the only entities able to produce a valid `X-Hub-Signature` for org `A` are GitHub itself and holders of `A`'s `webhook_secret` (an attacker who legitimately administers a GitHub App/org `A` that is also configured in this Shipit instance, e.g. because they onboarded their own org into a shared multi-tenant instance). That party has no write access to any stack belonging to org `B`.

After the attacker's request: the attacker crafts a JSON body where `repository.owner.login == "A"` (so `verify_signature` fetches and validates against `A`'s `webhook_secret`, which the attacker legitimately knows) but `repository.full_name == "B/some-repo"` (a repository actually tracked by Shipit under org `B`). They sign the raw body with `A`'s secret. `verify_signature` passes because it only checks the signature against `A`'s secret and never verifies that `full_name` is consistent with `owner.login`. `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` then dispatches to e.g. `PushHandler`, which resolves the target via `Repository.from_github_repo_name(repository_name)` using `full_name = "B/some-repo"` and calls `stack.sync_github(expected_head_sha: params.after)` — an org-`A`-authenticated request has caused a write/action against org `B`'s stack.

This is a direct analog of the reported bug class: a signature covers a payload, but a *field that the downstream logic actually acts on* (`repository.full_name`) is not cross-validated against the field used to select/verify the trust boundary (`repository.owner.login`), i.e. "an organization that authenticated versus the repository that is written."

### Impact Explanation
An attacker who is a legitimate GitHub App owner for **any** organization configured in a shared/multi-tenant Shipit instance (a scenario explicitly supported by the multi-org config schema in `docs/setup.md` and `lib/shipit.rb#github_app_config`) can forge webhook events (`push`, `status`, `check_suite`, `membership`, etc.) that are dispatched against **other organizations'** repositories/stacks tracked by the same instance, without holding write access to those repositories. Depending on the handler this can trigger `GithubSyncJob`, commit/status synchronization, or team/membership mutations against a repository the attacker does not control — an unauthorized cross-repository action, which meets the "cross-repository writes" High/Critical impact bar.

### Likelihood Explanation
Exploitability requires the Shipit instance to be configured with the multi-organization `github:` schema (more than one org's `webhook_secret`) and the attacker to control one of those onboarded orgs — a real, documented deployment configuration, not a hypothetical one. No GitHub App private key, no Shipit session, and no `api_clients_secret` are needed; only knowledge of one tenant's own `webhook_secret`, which that tenant necessarily possesses.

### Recommendation
After signature verification, re-derive `repository_owner` from the *verified* organization context and require that `repository.full_name`'s owner segment matches the organization whose secret validated the signature before dispatching to handlers. Reject the webhook (422) on mismatch, and log the discrepancy for auditing.

### Proof of Concept
1. Configure Shipit with two orgs, `A` and `B`, each with its own `webhook_secret` (`lib/shipit.rb#github_app_config`), and track a repo `B/target-repo` as a `Stack`.
2. As the operator of org `A` (who legitimately knows `A`'s `webhook_secret`), build a `push` payload:
   ```json
   { "ref": "refs/heads/main", "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "A" }, "full_name": "B/target-repo" } }
   ```
3. Compute `X-Hub-Signature: sha1=HMAC-SHA1(A_webhook_secret, raw_body)` and POST to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` looks up org `A`'s secret (via `repository_owner` = `"A"`), verification succeeds.
5. `PushHandler#process` resolves the stack via `Repository.from_github_repo_name("B/target-repo")` and calls `stack.sync_github(expected_head_sha: ...)`, acting on org `B`'s stack — despite the request only being authenticated as org `A`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
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
```
