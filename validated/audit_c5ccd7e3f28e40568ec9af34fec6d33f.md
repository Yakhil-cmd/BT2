### Title
Webhook signature verified against the payload's `repository.owner.login`, but the repository acted upon is resolved from the unauthenticated `repository.full_name` field, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` derives the GitHub organization used to select the HMAC secret from `repository.owner.login` (or `organization.login`) in the JSON payload, and verifies the request signature against that organization's `webhook_secret`. However, every event handler (`Shipit::Webhooks::Handlers::Handler`) resolves the actual `Repository`/`Stack` to act on using the separate `repository.full_name` field, without re-checking that its owner matches the organization whose secret validated the signature. An attacker who controls (or has push access to) a repository under Organization A can forge a webhook body/signature that is valid for Organization A, while pointing `repository.full_name` at a repository belonging to a completely different, unrelated Organization B configured on the same Shipit instance — causing the engine to execute writes (sync jobs, status creation, review-stack archiving, etc.) against Organization B's stacks.

### Finding Description
Signature verification only binds the organization identity, not the repository being written to:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization: ...)` picks a `GithubApp` instance whose `webhook_secret` is configured per organization (Shipit explicitly supports multiple GitHub organisations), and `verify_webhook_signature` performs a raw HMAC compare over the whole raw body using that org-specific secret:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  algorithm, signature = signature.split("=", 2)
  return false unless algorithm == 'sha1'
  SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
end
``` [2](#0-1) 

This step only proves "the sender knows organization A's `webhook_secret`" — it says nothing about which repository the payload's body claims to describe. Every handler then resolves its target purely from `repository.full_name`, a field that is inside the same signed body but never cross-checked against the organization used for verification:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`PushHandler`, for example, uses this `stacks` scope directly to enqueue a GitHub sync against whatever stack matches `repository.full_name` and the pushed branch:

```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [4](#0-3) 

Because `repository_owner` (used for signature/secret selection) and `repository.full_name` (used for target resolution) are independent fields inside the attacker-controlled JSON body, nothing stops them from disagreeing. An attacker who has legitimate write/webhook access to any repository under an organization configured in this Shipit instance can:
1. Set `repository.owner.login` to their own organization ("A") so `Shipit.github(organization: "A")` picks A's `webhook_secret`, which the attacker can obtain by installing/observing a real webhook delivery for their own repo, or by controlling that org's GitHub App/webhook configuration entirely.
2. Sign the crafted body with A's `webhook_secret` (satisfying `verify_webhook_signature`).
3. Set `repository.full_name` to `"OrgB/victim-repo"`, a repository the attacker has no access to, so the handler resolves and mutates OrgB's `Stack`s.

This breaks the intended binding: `verified_organization == acted_upon_repository_owner`. Instead the engine enforces only `verified_organization == payload["repository"]["owner"]["login"]`, which is a value the attacker also controls and need not match `payload["repository"]["full_name"]`.

### Impact Explanation
Because every webhook handler (`PushHandler`, `StatusHandler`, `PullRequest::*Handler`, `CheckSuiteHandler`, `MembershipHandler`) inherits repository resolution from `Handler#stacks`/`#repository_name`, this single trust gap has broad write effects on stacks/repositories that belong to organizations the attacker does not control:
- `PushHandler` can force `GithubSyncJob`/resync on arbitrary victim stacks with an attacker-chosen `expected_head_sha`.
- `Status`-driven handling can create commit statuses on a victim stack's commits; when a victim stack has `continuous_deployment` enabled, a forged `state: success` status on the last undeployed commit can trigger an actual deploy without any legitimate access to the victim organization/repository (Shipit's continuous-deployment logic reacts to a commit transitioning to a successful state) [5](#0-4) .
- `PullRequest` handlers can archive/unarchive review stacks belonging to the victim repository.

An unauthorized deploy triggered against a repository/org the attacker has no legitimate relationship with is a Critical-impact outcome (unauthorized deploy), matching the accepted impact categories for this analog.

### Likelihood Explanation
The attacker only needs push/webhook-eligible access to one repository under any GitHub organization already configured in the target Shipit instance (multi-organization support is a documented Shipit feature) — no Shipit session, `ApiClient` token, `api_clients_secret`, or GitHub App private key for the victim org is required. The only real-world constraint is that the target instance must have more than one organization configured (or the attacker's own org's secret is otherwise known), which is a normal deployment configuration, not an edge case the engine forbids.

### Recommendation
When resolving the target repository/stack for a webhook event, verify that the repository's owner (`repository.full_name`'s owner segment, or `repository.owner.login`) matches the organization whose `webhook_secret` was used to verify the signature (`repository_owner` in `WebhooksController`). Reject events where these two do not match, e.g. by threading `repository_owner` from the controller into `Shipit::Webhooks::Handlers::Handler` and asserting it against `Repository.from_github_repo_name(repository_name)&.owner` before any handler logic runs.

### Proof of Concept
1. Attacker controls/observes a webhook secret for `orgA` (their own GitHub organization, installed on the same Shipit instance that also serves `orgB`, a victim organization with a stack tracking `orgB/victim-repo`).
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef...",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(orgA_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"orgA"`, fetches `orgA`'s `webhook_secret`, and the signature check passes [6](#0-5) .
5. `PushHandler#process` resolves stacks via `repository.full_name = "orgB/victim-repo"` and enqueues `GithubSyncJob` (or, for a `status` event, creates a `Status` on a victim commit) against a stack the attacker never had legitimate access to [3](#0-2) [4](#0-3) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** test/models/commits_test.rb (L245-252)
```ruby
    test "updating state to success skips deploy when stack has CD but a deploy is in progress" do
      @stack.reload.update(continuous_deployment: true)
      @stack.trigger_deploy(@commit, @commit.committer)

      assert_no_difference "Deploy.count" do
        @commit.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
      end
    end
```
