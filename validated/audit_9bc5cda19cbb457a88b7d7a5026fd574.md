### Title
Webhook signature verification keys off `repository.owner.login`/`organization.login` while handlers act on `repository.full_name` / repo identity, enabling cross-organization webhook forgery in multi-tenant `github:` configurations - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) is used to verify the HMAC signature of an inbound webhook based solely on `repository.owner.login` (or `organization.login`) taken from the JSON body. Once verification passes, the entire raw payload — including `repository.full_name`, which is what downstream handlers use to resolve the target `Stack`/`Repository` — is dispatched unchanged to `Shipit::Webhooks.for_event(event)` handlers. There is no check binding the "owner" field used for secret selection to the repository identity that handlers actually act on.

### Finding Description
`Shipit.github(organization:)` supports a multi-tenant config where each GitHub organization key under `secrets.github` has its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` picks the app/secret to verify with using:

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

and then does:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [3](#0-2) 

If verification succeeds, `create` parses the *entire* raw body and hands it, unmodified, to every registered handler for the event:
```
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [4](#0-3) 

Handlers such as the push handler registered via `Shipit::Webhooks.default_handlers` resolve the target Stack/Repository from the payload's repository data (e.g. `repository.full_name`) [5](#0-4) , a field that is never checked against `repository_owner` (the field used to pick the verifying secret).

This is the same trust-binding flaw pattern as the reported bug: one field (`repository.owner.login`, used to *authorize/select the secret*) is decoupled from a different field that is actually *acted upon* (`repository.full_name`, used to identify which repository/stack gets written to). Just as the audited contract computed `rewardRate` from `rewardAmount` while crediting/spending `totalRewardAmount` (rollover included), Shipit verifies authenticity against one organization identity while operating on whatever repository identity the payload independently claims.

Concretely: any party who legitimately controls a GitHub App/organization entry configured in Shipit's multi-tenant `github:` secrets (and thus possesses that org's `webhook_secret`) can construct an arbitrary JSON body — setting `repository.owner.login`/`organization.login` to their own (correctly-configured) org so the HMAC check passes, while setting `repository.full_name` (and other repository fields the handler reads) to reference a *different* repository/stack tracked by the same Shipit instance under another tenant/organization. The signature check only validates that the byte content was signed with the secret belonging to the org named in that one field; it does not constrain the semantic content of `repository` used elsewhere in the same payload.

### Impact Explanation
A successfully forged payload is routed to real handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.), which can enqueue `GithubSyncJob`, update commit statuses, and — via `Stack#trigger_continuous_delivery` — cause an unrelated, victim-owned Stack to fetch/sync fabricated commit and status data or trigger a deploy job that the forger has no legitimate authority over, breaking the binding "organization that authenticated == repository that is written." This satisfies the "unauthorized deploy" / "cross-repository writes" Critical impact category, since the attacker crosses a repository trust boundary using credentials that only authorize a different, unrelated repository.

### Likelihood Explanation
Exploitation requires the deployment to use the multi-tenant `github:` configuration with more than one organization entry (each with its own `webhook_secret`), and requires the attacker to control (own/administer) at least one of the configured GitHub App installations/organizations — a legitimate but lower-privileged tenant relative to the victim repository. Given that scoping condition, forging the payload is straightforward (HMAC-SHA1 over an attacker-fully-controlled JSON body, no other integrity binding). This is not exploitable in a single-organization (single-secret) deployment, since then any valid signature already implies access to the only configured secret and there is no cross-tenant boundary to break; likelihood is therefore Medium, conditioned on multi-org configuration.

### Recommendation
Bind the field used to select the verifying secret to the field(s) handlers subsequently act on. Concretely: after verifying the signature, re-derive `repository_owner` from the same payload used by the handler (e.g., require `repository.full_name`'s owner segment or `repository.id` to equal the identity used for signature selection), or verify the signature against the config that owns the specific `repository.id`/`full_name` a handler will operate on, rejecting the request if the two identities diverge. As defense-in-depth, additionally scope `Shipit::Webhooks` handler lookups against the `Repository`/`Stack` actually registered for the verified organization before performing any DB writes or job enqueues.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `orgA` (attacker-controlled installation, secret `S_A`) and `orgB` (victim, secret `S_B`), each tracking their own Stacks.
2. Attacker crafts a JSON payload:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo", "id": <orgB repo id> },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S_A, raw_body)` (they legitimately know `S_A`).
4. `POST` this to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` computes `repository_owner == "orgA"`, calls `Shipit.github(organization: "orgA")`, and the signature verifies successfully against `S_A` [3](#0-2) .
6. `create` dispatches the full payload — whose `repository.full_name` is `orgB/victim-repo` — to `PushHandler`, which resolves and syncs/deploys the victim's stack, despite the requester never having possessed `orgB`'s `webhook_secret`.

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

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
      end
```
