### Title
Cross-tenant webhook confused deputy: `repository_owner` (signature selector) and `repository.full_name` (target selector) are independently attacker-controlled, letting one organization's signed payload mutate another organization's stack - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`Shipit::WebhooksController#repository_owner` picks the verifying GitHub App/secret from `params.dig('repository','owner','login') || params.dig('organization','login')`, while `LabelCapturingHandler#repository` independently resolves the target stack from `params.repository.full_name`. Because the handler's `ExplicitParameters` schema only requires `repository.full_name` (not `repository.owner.login`), an attacker who legitimately controls one onboarded GitHub organization (and thus its webhook secret) can sign a `pull_request` `labeled` payload with their own org's secret while pointing `repository.full_name` at a victim organization's repository, letting `LabelCapturingHandler` write attacker-chosen data onto the victim's `PullRequest`/review stack.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:
`verified_secret_owner(repository_owner) == target_repository_owner(repository.full_name)`.

Trace:
- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) selects the GitHub App config via `repository_owner`, defined at line 59-62 as `params.dig('repository','owner','login') || params.dig('organization','login')`.
- `LabelCapturingHandler`'s schema (lines 33-35) only `requires :repository do requires :full_name, String end` — it never requires `repository.owner.login`.
- The handler resolves the actual target via `repository` (lines 110-114): `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, completely independent of whatever value was used for `repository_owner`.

An attacker who is a legitimate member of some GitHub organization onboarded to this multi-tenant Shipit instance (and therefore possesses/derives that organization's own webhook secret through normal GitHub webhook delivery for their own org, since they can emit real webhooks from a repo they own in that org) can instead construct a raw POST to `/webhooks` where:
- `repository` = `{ "full_name": "victim-org/victim-repo" }` (no `owner` key, satisfying the schema without matching a real owner),
- `organization` = `{ "login": "attacker-org" }` (the attacker's own onboarded org),
- signed with `attacker-org`'s webhook secret.

`verify_signature` computes `repository_owner = "attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and the signature validates successfully because it was genuinely signed with that org's secret. `drop_unhandled_event`/`ExplicitParameters` validation passes because only `full_name` is required. The handler then loads the stack for `victim-org/victim-repo`, and if a matching review stack/PR exists, `capture_labels` (lines 98-102) persists `params.pull_request.labels.map(&:name)` onto that victim `PullRequest` via `pull_request.update!(labels: ...)`, regardless of which org's secret authenticated the request.

No guard cross-checks that `repository.full_name`'s owner matches the organization/secret that authenticated the webhook — `verify_signature` and the handler's repository resolution operate on two independently attacker-suppliable fields.

### Impact Explanation
The `LabelCapturingHandler` writes into `victim-org/victim-repo`'s `PullRequest#labels` despite the request being authenticated only for `attacker-org`. This is a write for a repository that did not authenticate the request — matching the Critical category "a payload for one repository mutating another's stack." Downstream, if labels feed into `ReviewStack#env` as uppercased environment keys, and the victim stack has `continuous_deployment` enabled, attacker-controlled label-derived environment values can be picked up by the next `ContinuousDeliveryJob` deploy of that stack, extending impact toward unauthorized/altered deploys. This is repeatable against any repository/organization for which the attacker can guess or observe a `full_name`, as long as the attacker controls at least one other onboarded organization's webhook secret (their own).

### Likelihood Explanation
Preconditions: the Shipit instance must be multi-tenant (multiple GitHub organizations configured, each with its own webhook secret) — which is a standard/documented Shipit deployment model (`Shipit.github`/`Shipit.github_teams` config keyed by organization). The attacker needs no special privilege on the victim beyond knowing/guessing the victim's `owner/repo` full name and having an active review-stack/PR whose `Repository.from_github_repo_name` matches; they need only be a legitimate participant (repo owner/webhook sender) in their own, separately onboarded organization to obtain a valid signature for `verify_signature`. This is a real, low-cost, repeatable path within the engine's own trust boundary, not reliant on stolen secrets.

### Recommendation
- Require and enforce `repository.owner.login` in every handler's `ExplicitParameters` schema (not just `full_name`), and compare it against the same value used for `repository_owner` in `verify_signature`.
- In `WebhooksController`, remove or restrict the `organization.login` fallback for `repository_owner` when a `repository` object is present in the payload; if `repository.owner.login` is absent, reject the event rather than falling back to a different, independently controlled field.
- Additionally, in each handler's `repository` resolution, verify the resolved repository's owner matches the organization whose secret authenticated the request (defense in depth against the fields diverging).

### Proof of Concept
Minitest plan (test/controllers/webhooks_controller_test.rb or handler test):
1. Configure two organizations in `Shipit.github` config with distinct webhook secrets: `attacker-org` (secret `S_A`) and `victim-org` (secret `S_V`).
2. Create `victim-org/victim-repo` `Shipit::Stack` with `continuous_deployment: true` and an active review stack/PR (`Shipit::PullRequest`) with `number: 42`.
3. Build payload:
```json
{
  "action": "labeled",
  "number": 42,
  "pull_request": { ... , "labels": [{"name": "MALICIOUS_ENV=evil"}] },
  "repository": { "full_name": "victim-org/victim-repo" },
  "organization": { "login": "attacker-org" },
  "sender": { "login": "attacker" }
}
```
4. Sign with `S_A` (attacker-org's secret) and send `POST /webhooks` with header `X-Github-Event: pull_request`.
5. Assert:
   - `verify_signature` accepts (response is not 422) — i.e. `repository_owner` resolves to `"attacker-org"` and passes with `S_A`.
   - Before: `victim_pull_request.labels` does not contain `"MALICIOUS_ENV=evil"`.
   - After processing: `victim_pull_request.reload.labels` **does** contain `"MALICIOUS_ENV=evil"`, proving a request authenticated for `attacker-org` mutated `victim-org`'s `PullRequest`.
   - Assert the equality `repository_owner (attacker-org) != Repository.from_github_repo_name(params.repository.full_name).owner (victim-org)` to demonstrate the divergence explicitly. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L33-39)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-114)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```
