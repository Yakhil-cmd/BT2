### Title
Cross-organization webhook confusion in `WebhooksController#verify_signature` allows a webhook signed with one organization's secret to write to another organization's repositories/stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a request's HMAC against using `repository_owner`, taken from the *same unverified* JSON body it is about to validate. Downstream event handlers, however, decide *what repository/commit/stack to mutate* using different, independent fields of that same unverified body (`repository.full_name`, or in the `status` handler, no repository scoping at all). Because the field used to pick the verifying secret is never cross-checked against the field used to select the target of the write, an attacker who legitimately controls one organization's webhook secret (a normal, unprivileged tenant on a multi-org Shipit installation) can forge a validly-signed webhook whose payload claims to originate from their own org while its write-target fields point at a completely different organization's repository/stack.

### Finding Description
The relevant code:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`verify_signature` proves only that *some* field of the body (`repository.owner.login`) matches the org whose secret produced the HMAC over the raw body. It does not restrict which repository/commit/stack the handlers are allowed to touch. Handlers instead resolve their target independently:

```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`repository.full_name` and `repository.owner.login` are two distinct JSON fields inside the same unauthenticated body, and nothing enforces `full_name`'s owner segment equals `owner.login`. Worse, `StatusHandler` does not even use `repository_name`/`stacks` scoping at all:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

so it can update the CI status of a commit belonging to *any* stack on the entire Shipit instance, as long as *any* configured org's webhook secret was used to sign the request. `ClosedHandler`/`LabeledHandler` for pull requests do scope by `repository.full_name`, but that field is completely independent from the field checked in `verify_signature`:

```ruby
def repository
  @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                  Shipit::NullRepository.new
end
...
def process
  return unless respond_to_pull_request_closed?
  review_stack.archive!
end
``` [4](#0-3) 

The binding that should hold as an equality is:

`organization authenticated by verify_signature (repository_owner) == organization owning the repository/stack/commit that the handler writes to`

This equality is never enforced; the write path trusts a second, unrelated field from the same untrusted payload.

### Impact Explanation
On a Shipit instance configured with multiple GitHub organizations (as explicitly supported by `config/secrets.yml`, see `github: <org>: webhook_secret: ...` blocks) [5](#0-4) , any organization admin who legitimately owns a webhook secret for their own, unprivileged org can forge webhook deliveries that are cryptographically valid (per `verify_webhook_signature`) yet mutate state belonging to a completely different organization's repositories/stacks:
- `StatusHandler` lets them inject a fabricated CI status (e.g. `state: "success"`) onto any commit in any stack in the installation, which can be used to satisfy status-based deploy gating for a victim's stack, enabling an **unauthorized deploy**.
- `PullRequest::ClosedHandler`/`LabeledHandler` let them archive/unarchive a victim organization's review stacks (`review_stack.archive!`, `stack.archive!`/`unarchive!`), a **cross-repository write** to state they have no legitimate access to.
- `PushHandler` lets them trigger `GithubSyncJob` against an arbitrary victim stack with an attacker-chosen `expected_head_sha`.

This satisfies the "cross-repository writes" / "unauthorized deploy" criteria because the trust boundary crossed is exactly the authenticated-organization vs. written-repository binding.

### Likelihood Explanation
Requires the attacker to control (or be an admin of) at least one organization that is legitimately configured on the shared Shipit instance — no privileged Shipit account, `ApiClient` token, or `GITHUB_TOKEN` is needed, only the ability to send an arbitrary HTTP POST with a signature computed from a webhook secret they legitimately possess for their own org. This matches the "unprivileged attacker breaking a deployment-trust binding" pattern described in the report (organization authenticated vs. repository written).

### Recommendation
Enforce that the value used to select the verifying webhook secret is the same value used to resolve the target repository/stack/commit for every handler, e.g.: derive `repository_owner` for verification from `repository.full_name` (splitting on `/`) rather than the separate `repository.owner.login`/`organization.login` fields, and have every handler (especially `StatusHandler`) scope lookups through the `Repository` resolved from that same authenticated owner rather than an independently-controlled field of the payload.

### Proof of Concept
1. Attacker is an admin of `attacker-org`, a GitHub organization that has the Shipit GitHub App installed and is configured in this Shipit instance's `secrets.yml` with its own `webhook_secret`.
2. Attacker crafts a `status` webhook payload:
```json
{
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/whatever"},
  "sha": "<victim-org's commit sha, gated for deploy>",
  "state": "success",
  "context": "required-ci-check"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org's webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s app/secret, and the signature checks out — request is accepted [6](#0-5) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` with no ownership check and creates a status on the victim's commit [3](#0-2) , potentially satisfying a deploy-blocking check for a repository the attacker has no relationship to.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
