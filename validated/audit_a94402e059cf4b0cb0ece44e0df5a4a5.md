### Title
Webhook signature verification is scoped by `repository.owner.login`, not by the repository that is actually written - allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit deployment, `WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` used to authenticate an inbound webhook based on `repository.owner.login` (falling back to `organization.login`), but the handler that performs the actual write (locating and syncing/deploying a `Stack`) resolves the target repository from a *different*, unauthenticated field: `repository.full_name`. Because these two fields are never checked against each other, an attacker who knows the webhook secret for *one* onboarded GitHub organization can forge a validly-signed payload whose `repository.full_name` points at a *different* organization's repository, causing Shipit to act (e.g. enqueue a `GithubSyncJob`) on a stack that attacker's secret was never meant to authorize.

### Finding Description
`Shipit.github(organization:)` supports a multi-tenant configuration where each onboarded GitHub organization has its own `webhook_secret` in `secrets.github`: [1](#0-0) 

The webhook entry point verifies the signature using the app selected by `repository_owner`, which is read straight from the untrusted JSON payload: [2](#0-1) [3](#0-2) 

The signature check itself is a straightforward HMAC comparison against the secret configured for the organization selected above: [4](#0-3) 

Once the signature passes, `create` dispatches the *entire* raw payload to the matching event handler(s): [5](#0-4) 

But the handler resolves which `Stack`/`Repository` to act on using an entirely different JSON field — `repository.full_name` — with no cross-check against `repository.owner.login`/`organization.login` that was used for signing: [6](#0-5) 

For example, the push handler uses that `stacks` helper (scoped by `repository_name`) to enqueue a sync against matching, non-archived stacks: [7](#0-6) 

**The broken binding:** `repository_owner` (the field the signature authenticates) is expected to equal the owner embedded in `repository.full_name` (the field whose `Stack` gets written to), but nothing in the code enforces `repository.owner.login == repository.full_name.split('/').first`. These are independent, attacker-controlled keys in the same forged JSON body. Since the JSON is fully attacker-supplied (only its HMAC over the whole raw body is checked, using the secret keyed off `repository.owner.login`), an attacker who has been given/knows one organization's `webhook_secret` (e.g., because they are the GitHub org admin who configured that org's webhook integration with Shipit, which is a normal, unprivileged-relative-to-other-orgs step in onboarding a multi-tenant install) can set:
- `repository.owner.login` = "OrgA" (their own org, so the HMAC verification passes against OrgA's secret)
- `repository.full_name` = "OrgB/target-repo" (a different organization's repository tracked by the same Shipit instance)

and the request will pass `verify_signature`, then dispatch to handlers that act on `OrgB/target-repo`'s stacks — an organization the attacker never authenticated against.

### Impact Explanation
This breaks the trust boundary between separately onboarded GitHub organizations sharing one Shipit instance. Concretely, with a forged `push` event an attacker can trigger `GithubSyncJob` for another organization's stacks (`PushHandler#process`), and other handlers keyed the same way (pull_request handlers, `membership`, `status`, `check_suite`, etc.) are equally reachable for cross-org repositories, since `Handler#repository_name`/`#stacks` is the common resolution path for essentially all webhook handlers. Depending on which handler is targeted this can influence CI status marking, merge-request bookkeeping, or trigger sync jobs against a stack that does not belong to the attacker's organization — an unauthorized cross-repository/cross-organization action performed using credentials (webhook secret) that were never meant to authorize writes on that target repository. This matches the "cross-repository writes" / "unauthorized deploy" class of impact called out as Critical, though the practical blast radius depends on which specific handler is abused (some handlers, like sync jobs, are a step removed from an actual deploy).

### Likelihood Explanation
Requires the attacker to already know the `webhook_secret` for at least one organization onboarded to the same multi-tenant Shipit instance — which is realistic for an org that self-configures its own GitHub webhook against a shared Shipit deployment, since org admins typically choose/see their own webhook secret when wiring up the integration. Given that, forging the payload is trivial: no other credential (GitHub token, session, API client key) is needed. Likelihood is moderate-to-high specifically in multi-organization deployments; it does not apply to the common single-organization deployment where `github_default_organization` is nil (no owner-based secret selection occurs).

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), enforce that the repository/organization actually acted upon matches the organization whose secret validated the signature. Concretely, after selecting `repository_owner` for signature verification, also verify that `payload.dig('repository', 'full_name')&.split('/')&.first` (case-insensitively) equals `repository_owner` before dispatching to handlers, rejecting the request (e.g. `head(422)`) on mismatch. Alternatively, pass the authenticated `repository_owner` into the handler and have `Handler#stacks`/`#repository_name` resolve repositories scoped to that verified organization rather than trusting the payload's `full_name` independently.

### Proof of Concept
1. Deploy Shipit in multi-org mode: `secrets.github` contains `orga: { webhook_secret: "secretA", ... }` and `orgb: { webhook_secret: "secretB", ... }`, with stacks tracked for repositories under both `OrgA/*` and `OrgB/*`.
2. Attacker is (or compromises) the party responsible for configuring OrgA's GitHub webhook against this Shipit instance and thus knows `secretA`.
3. Attacker crafts a JSON payload for the `push` event:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/target-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(secretA, raw_body)>` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` calls `repository_owner` → `"OrgA"`, selects `Shipit.github(organization: "OrgA")`, verifies the HMAC against `secretA` — passes, because the body was legitimately signed with `secretA` (`app/controllers/shipit/webhooks_controller.rb:24-49,59-62`; `lib/shipit/github_app.rb:76-83`).
6. `create` dispatches the same payload to `PushHandler`, whose `repository_name` reads `payload.dig('repository', 'full_name')` → `"OrgB/target-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), resolving and syncing `OrgB`'s stacks (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) — despite the request never being authenticated by anything belonging to `OrgB`.

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
