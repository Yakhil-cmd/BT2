### Title
Signature verification is scoped to the org derived from `repository.owner.login`, but the webhook payload's `repository.full_name` (a different, uncorrelated field) drives which Stack/repository the event actually acts on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the HMAC signature against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login`). Once the signature check passes, the actual event handlers (`PushHandler`, `pull_request` handlers, etc.) locate the target `Repository`/`Stack` using an entirely separate JSON field, `repository.full_name`, via `Repository.from_github_repo_name`. Nothing binds these two fields together, so the org whose secret authenticated the request is not guaranteed to be the org/repo the handler actually mutates.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` (lines 24-49, 59-61) does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

The signature is checked against the secret configured for whichever organization is named in `repository.owner.login`, which is itself just a JSON field inside the same attacker-controlled body being verified. This is a legitimate scoping mechanism for Shipit's multi-org configuration (`config/secrets.*.yml` documents per-organization `webhook_secret` entries).

However, once `verify_signature` passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full raw params to handlers. Every handler resolves the target repository independently, using `repository.full_name`, not `repository.owner.login`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
``` [3](#0-2) 

`PushHandler` uses this to sync any stack matching the pushed branch:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [4](#0-3) 

Pull-request handlers do the same with `params.repository.full_name`:
```ruby
def repository
  @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
end
``` [5](#0-4) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the acted-upon repository) are two independent JSON keys with no cross-field validation, an attacker who possesses a valid webhook secret for *any one* organization configured in the Shipit instance can craft a body where:
- `repository.owner.login` = the org whose secret they hold (so `verify_signature` succeeds), and
- `repository.full_name` = `"<other-org>/<other-repo>"` (so the handler acts on a completely different organization's stack).

This breaks the binding: *organization authenticated == repository written*, which the rules explicitly call out as an in-scope trust boundary.

### Impact Explanation
An attacker who administers (or otherwise legitimately controls the GitHub App/webhook secret of) one small, low-privilege organization onboarded to a shared Shipit instance can forge signed-looking webhook events (`push`, `pull_request`, `status`, `check_suite`, etc.) that are processed as if they came from a completely different, higher-privilege organization's repository. Concretely:
- A forged `push` event with `repository.full_name` pointing at a victim org's stack triggers `stack.sync_github(expected_head_sha: ...)`, injecting an attacker-chosen "latest" commit SHA into the victim stack's Git history tracking, which can be leveraged to affect what gets deployed/rolled back.
- A forged `status` event can inject fake CI status entries against the victim repo's commits, which is exactly the kind of signal Shipit's deploy pipeline uses to gate deploys, potentially enabling an **unauthorized deploy**.
- A forged `pull_request` event (opened/labeled/reopened) can create/unarchive/archive `ReviewStack`s for a victim repository the attacker does not otherwise have access to.

This matches the report's "Critical: unauthorized deploy" impact category, since the mismatch lets a party with signing rights for one org influence stack state/deploy readiness for another org's repository.

### Likelihood Explanation
Medium: this requires the attacker to hold a valid webhook secret for at least one organization configured in the same Shipit instance (multi-org setups are explicitly documented in `config/secrets.development.shopify.yml` and `docs/setup.md`). This is not a "privileged Shipit account" - just administrative control of one org's GitHub App configuration, which is far weaker than write access to the victim's repository. In single-org Shipit deployments this issue is not exploitable (there is only one secret, and `repository.owner.login` and `repository.full_name`'s owner would trivially match unless the attacker also owns that one org). It is exploitable specifically in the multi-org configuration Shipit's own documentation describes as supported.

### Recommendation
Cross-validate that `repository.owner.login` (or `organization.login`) used for signature verification matches the owner segment of `repository.full_name` used by the handler layer, and reject the webhook if they diverge. Alternatively, have handlers resolve the repository/organization scope directly from the same field that was authenticated (`repository_owner`), rather than independently re-deriving it from `repository.full_name`.

### Proof of Concept
1. Shipit is configured with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `config/secrets.*.yml` multi-org format).
2. Attacker administers `OrgA`'s GitHub App and knows `OrgA`'s `webhook_secret`.
3. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature` using `OrgA`'s webhook secret over this exact raw body and POSTs it to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "OrgA")`, whose secret matches, so the signature check passes.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `OrgB`'s stack, even though the signing organization was `OrgA`.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-61)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
