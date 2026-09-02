### Title
Webhook signature verified against the organization derived from the payload while the acted-upon repository is resolved from a different, unchecked payload field - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` picks the HMAC secret to validate a webhook against by reading `repository_owner` out of the **untrusted** JSON payload, then verifies the raw body against that organization's `webhook_secret`. The event handlers (e.g. `PushHandler`) subsequently resolve which `Repository`/`Stack` to mutate using a **separate** field from the same payload (`repository.full_name`), with no re-check that this repository actually belongs to the organization whose key validated the signature.

### Finding Description
In a multi-organization Shipit deployment (`config/secrets.yml` with one `github:` entry per org, see `Shipit.github_organizations`/`Shipit.github_app_config`), each organization has its own `webhook_secret`. [1](#0-0) 

The signature check looks up the org purely from payload content: [2](#0-1) [3](#0-2) 

`verify_webhook_signature` only checks the HMAC against whatever secret was resolved for that `repository_owner`: [4](#0-3) 

Once the signature passes, `create` re-parses the same raw body and dispatches to a handler: [5](#0-4) 

Handlers resolve the target `Repository`/`Stack` using a **different** JSON key, `repository.full_name`, with no cross-check that this repository's owner matches the `repository_owner`/`organization.login` value used for signature verification: [6](#0-5) [7](#0-6) 

This breaks the binding: **organization whose secret authenticated the request == organization that owns the repository being written to**. Concretely, an attacker who legitimately controls a GitHub organization/repo configured in this Shipit instance (and thus possesses that org's genuine `webhook_secret`, delivered by GitHub itself for their own repo's events) can craft a raw HTTP request where:
- `repository.owner.login` (or `organization.login`) = their own org A (so `verify_signature` fetches org A's secret and the HMAC computed with that secret validates), while
- `repository.full_name` = `orgB/some-other-tracked-repo` (a completely different organization's stack tracked by the same Shipit instance).

Because the HMAC is computed over the raw body and org A's secret is a valid secret for a body they control, the signature check passes, and `PushHandler`/`StatusHandler`/`CheckSuiteHandler` etc. will act on org B's stack (triggering `sync_github`, commit status updates, check-run refreshes, PR-driven review-stack lifecycle actions) despite the request never being signed with org B's key.

### Impact Explanation
This allows an actor who only controls one organization/repo in a shared, multi-org Shipit deployment to forge webhook events (push syncs, status updates, check-suite refreshes, PR opened/closed/labeled events driving review-stack creation/merge/deploy triggers) against stacks belonging to a completely different GitHub organization that they have no access to. Depending on which handler is reached, this can trigger unintended repository syncs, spurious/forged commit statuses influencing deploy safety checks, or review-stack lifecycle transitions (merge, deploy) for a repository the attacker does not control — a cross-repository/cross-organization integrity violation via a credential (webhook secret) that was never issued for the targeted repository.

### Likelihood Explanation
Requires a multi-organization Shipit configuration (`Shipit.github_organizations` with more than one org key) where the attacker legitimately owns one configured organization/repo and thus holds a valid `webhook_secret` for it, then sends a directly-crafted HTTP POST to `/webhooks` (not via GitHub) with a mismatched `repository.full_name`. No compromise of the target org's credentials, GitHub App, or session is required — only possession of one's own legitimate configured webhook secret, satisfying the "unprivileged attacker" analog to the original relayer/oracle mismatch bug class (verification and action operate on two different, independently-trusted fields).

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#stacks`), enforce that the repository resolved via `repository.full_name` actually belongs to the same organization/owner that was used to select the verifying `webhook_secret` — i.e., re-derive `repository_owner` from the resolved `Repository`'s stored owner and compare it against the payload's owner used for the HMAC lookup, rejecting the request (422) on mismatch.

### Proof of Concept
1. Configure Shipit with two orgs, `org-a` and `org-b`, each with its own `webhook_secret` (multi-org schema in `config/secrets.yml`).
2. Attacker controls `org-a` and its repo `org-a/repo`, and thus legitimately knows `org-a`'s `webhook_secret` (it's the org admin's own secret they set on their GitHub App/webhook config).
3. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-controlled sha or existing sha of org-b's tracked repo>",
  "repository": { "full_name": "org-b/target-repo", "owner": { "login": "org-a" } }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<hmac(org-a webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` reads `repository_owner` from `params.dig('repository','owner','login')` → `"org-a"`, fetches `org-a`'s secret via `Shipit.github(organization: 'org-a')`, and the HMAC validates because it was in fact computed with `org-a`'s real secret. Signature check passes (`app/controllers/shipit/webhooks_controller.rb:24-49`).
6. `create` dispatches to `PushHandler`, whose `stacks` lookup uses `payload.dig('repository','full_name')` = `"org-b/target-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), triggering `sync_github` on `org-b`'s stack — an action never authorized by `org-b`'s webhook secret.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
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
