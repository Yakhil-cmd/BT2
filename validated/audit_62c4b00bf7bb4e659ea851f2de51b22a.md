### Title
Cross-tenant `PullRequest` cache poisoning via decoupled webhook-signature org and target-repository lookup - (File: `app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against using `params.dig('repository','owner','login')` (falling back to `organization.login`), while `EditedHandler#pull_request` resolves the target `PullRequest`/`Repository` using the independent JSON field `params.dig('repository','full_name')`. Because both fields are read from the same attacker-supplied JSON body, and there is no assertion that `full_name`'s embedded owner matches `repository.owner.login`, an attacker who is a legitimately onboarded (but unprivileged) Shipit organization can craft a payload that verifies under their own org's secret while pointing the repository lookup at an unrelated victim repository/PR.

### Finding Description
The claimed binding is: `repository_owner_used_for_signature (params.repository.owner.login or params.organization.login) == owner_of_repository_targeted_by_handler (parsed from params.repository.full_name)`.

Tracing the code:
- `WebhooksController#verify_signature` at [1](#0-0)  computes `github_app = Shipit.github(organization: repository_owner)` and verifies the raw body's HMAC signature against that org's `webhook_secret`.
- `repository_owner` is defined independently at [2](#0-1)  as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — a distinct JSON path from `repository.full_name`.
- `EditedHandler#pull_request` and `EditedHandler#repository` resolve the target repository/PR solely from `params.repository.full_name`: [3](#0-2) , calling `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, which does `github_repo_name.downcase.split('/')` and `find_by(owner:, name:)`: [4](#0-3) .
- Nowhere in this call chain is `repository.owner.login` (used to pick the signing secret) checked against the owner segment parsed out of `repository.full_name` (used to find the DB row). Both fields are entirely attacker-controlled content of the same raw JSON body, since the attacker builds the whole payload themselves to send to `POST /webhooks`.
- `EditedHandler#process` then unconditionally writes attacker-controlled JSON onto the matched row: `pull_request.update(github_pull_request: params.pull_request) if pull_request.present?` [5](#0-4) , including attacker-chosen `head.sha`/`head.ref`/`title` per the `ExplicitParameters` schema [6](#0-5) .

Exploit flow: an attacker who owns a Shipit-registered organization (e.g. because they are a legitimate, unprivileged tenant of a multi-org Shipit deployment, per `config/secrets.development.shopify.yml`'s multi-org schema and `Shipit.github_app_config`) knows or can obtain a validly signed webhook envelope for their own org (`repository.owner.login = "attacker-org"`, or by using the `organization.login` fallback). They then set `repository.full_name = "victim-org/victim-repo"` and `number` to a real victim PR number, and `pull_request.head.sha/ref/title` to attacker-chosen values, and POST this JSON with a valid `X-Hub-Signature` computed with attacker-org's secret. `verify_signature` passes because it only checks the secret keyed by `attacker-org`; `EditedHandler` then loads and overwrites the victim's `PullRequest#github_pull_request` cache.

None of the listed guards catch this: `verify_signature` checks a signature against a secret chosen by a field that is never cross-checked against the lookup field; `drop_unhandled_event` only checks the event type exists; the `ExplicitParameters` schema only validates types/presence, not cross-tenant ownership; there's no `force_github_authentication`, `User#authorized?`, or `require_permission!` in this webhook path at all — it is unauthenticated by design (webhooks don't carry a Shipit session/API token), relying entirely on the HMAC signature for trust, and that HMAC trust is exactly what's being bypassed for the wrong resource.

### Impact Explanation
A successful request lets a single attacker-controlled org silently overwrite another tenant's `PullRequest#github_pull_request` JSON cache — including `head.sha`, `head.ref`, and `title` — for any `(number, repository)` pair they can guess/enumerate, as long as they can produce one validly-signed webhook body for an org they control. This is a cross-tenant write: a payload delivered/signed for one repository/org mutates another repository's stored data. If downstream logic (merge queue decisions, deploy/rollback triggers, status checks) trusts `github_pull_request['head']['sha']` from this cache rather than re-fetching from GitHub, this can influence merge or deploy behavior for the victim, matching the "payload for one repository mutating another's stack/commit/task/team" Critical category. It is repeatable against any victim `(repository, PR number)` combination and is not limited to a single request.

### Likelihood Explanation
Preconditions: the Shipit deployment must be multi-tenant (multiple GitHub orgs configured under `github:` per docs/setup.md's "Using Multiple Github Applications" section), and the attacker must be one such onboarded org with a working webhook (which, per the threat model, is available to any unprivileged org owner able to receive/emit webhooks for their own repo — this is exactly the "verified under attacker's org" precondition stated in the question). The attacker also needs a victim `PullRequest` row to exist for the guessed/known `(number, repository)`. No secrets need to be stolen; the attacker only needs the ability to produce a validly signed payload for their own org, which is inherent to being a legitimate tenant. Feasibility is high and the attack is trivially repeatable (single POST per victim PR/number).

### Recommendation
In `EditedHandler` (and the sibling `PullRequest` handlers using the same `from_github_repo_name`/`repository_owner` pattern), enforce that the org used to verify the webhook signature is the same org that owns the repository referenced by `repository.full_name` before performing any lookup/update — e.g., have `WebhooksController` (or a shared concern) assert `repository.full_name.split('/').first.casecmp?(repository_owner)` and reject (422) on mismatch, or have handlers derive the target repository strictly from the same verified owner rather than trusting a second, unchecked field in the same payload.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/pull_request/edited_handler_test.rb (add to existing test class)

test "cross-org payload can overwrite a PullRequest owned by a different repository/org" do
  victim_pr = shipit_pull_requests(:review_stack_review) # belongs to some victim stack/repository
  victim_repo = victim_pr.stack.repository

  payload = payload_parsed(:pull_request_opened)
  payload["action"] = "edited"
  payload["number"] = victim_pr.number
  # attacker fully controls this sub-object
  payload["pull_request"]["head"]["sha"] = "deadbeefattackercontrolledsha"
  payload["pull_request"]["title"] = "attacker title"
  # attacker sets full_name to the victim repo, independent of owner.login
  payload["repository"]["full_name"] = victim_repo.github_repo_name
  # owner.login (used only for signature-org selection) stays as attacker's own org
  payload["repository"]["owner"]["login"] = "attacker-org"

  assert_changes -> { victim_pr.reload.github_pull_request.dig('head', 'sha') },
                 to: "deadbeefattackercontrolledsha" do
    EditedHandler.new(payload).process
  end
end
```

Note: this PoC exercises `EditedHandler#process`/`#pull_request` directly, matching how `WebhooksController#create` invokes handlers only after `verify_signature` has independently validated the signature against `repository_owner` (`attacker-org`) — a check that is orthogonal to, and does not constrain, the `repository.full_name` field consumed by the handler.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_edited?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L49-65)
```ruby
          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
