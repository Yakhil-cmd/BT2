### Title
Cross-tenant PR metadata poisoning via `repository.owner.login`/`repository.full_name` mismatch in webhook signature scoping - (File: app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a webhook using only `params.dig('repository', 'owner', 'login')` to select which org's `webhook_secret` to check against, while `EditedHandler` (and its sibling `AssignedHandler`) independently resolve the target `Repository`/`PullRequest` using `params.repository.full_name`. Nothing binds these two fields together, so an attacker who legitimately controls one org's webhook secret can sign a payload whose `repository.owner.login` matches their own org but whose `repository.full_name`/`number` point at a different org's tracked repository and PR, causing `pull_request.update(github_pull_request: params.pull_request)` to overwrite a victim tenant's cached PR metadata.

### Finding Description
The claimed binding is: `repository_owner` used for signature verification (ORG_A, derived from `params.dig('repository','owner','login')` in `app/controllers/shipit/webhooks_controller.rb:59-62`) == the org owning the `PullRequest` mutated in `EditedHandler#process` (ORG_B, derived from `Shipit::Repository.from_github_repo_name(params.repository.full_name)` in `app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb:63-65`).

These are two separate reads of the same untrusted, attacker-supplied JSON body, with no validation that `repository.owner.login` is actually a prefix of `repository.full_name`. `ExplicitParameters` only enforces types (`String`), not consistency between them [1](#0-0) .

Path:
1. `WebhooksController#verify_signature` picks the GitHub app config via `Shipit.github(organization: repository_owner)` and validates the HMAC signature against that org's `webhook_secret` [2](#0-1) .
2. If the attacker controls (or has configured) ORG_A's webhook secret — a legitimate capability for anyone who owns/administers an org's GitHub webhook — they can compute a valid `X-Hub-Signature` for an arbitrary payload body via `HMAC-SHA1` (`verify_webhook_signature` in `lib/shipit/github_app.rb:76-83`), and POST it directly to `/webhooks` (explicitly in-scope per the threat model).
3. In that payload they set `repository.owner.login = "ORG_A"` (to pass verification) but `repository.full_name = "ORG_B/victim-repo"` and `number = <victim PR number>`.
4. `Shipit::Webhooks.for_event('pull_request')` dispatches to `EditedHandler`, which resolves `repository` via `Repository.from_github_repo_name(params.repository.full_name)` — pointing at ORG_B's repository — and finds the matching `PullRequest` scoped to that repository's stacks [3](#0-2) .
5. `pull_request.update(github_pull_request: params.pull_request)` overwrites the victim's cached PR `title`, `state`, `head.sha`/`ref`, `labels`, `assignees`, etc. with attacker-chosen values [4](#0-3) .

`AssignedHandler` has the identical structure and is equally vulnerable [5](#0-4) . This is the same class of bug reachable via a different `action` value (`edited` vs `assigned`/`unassigned`), confirming the pattern is systemic across all `PullRequest` handlers that use `repository.full_name` for the lookup but never re-validate it against the org whose secret authenticated the request.

Existing guards do not close this gap: `verify_signature` only proves the request was signed by *some* org's key, not that the *contents* of `repository.full_name`/`number` belong to that org; `drop_unhandled_event` and the `ExplicitParameters` schema (`app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb:8-39`) only check event routing and payload shape, not cross-field consistency; there is no model validation on `PullRequest` or `Stack` that re-derives ownership from the authenticated org.

### Impact Explanation
An attacker who controls any single org's webhook configuration in Shipit (i.e., knows that org's `webhook_secret`) can forge arbitrary `pull_request` `edited`/`assigned`/`unassigned` events against **any other tenant's repository and PR** tracked by the same Shipit instance, repeatably and for arbitrary PR numbers, overwriting `title`, `state`, `head.sha`, `head.ref`, `labels`, and `assignees` fields in the victim's `PullRequest#github_pull_request` cache. This is a cross-tenant record write where the repository whose data is mutated never authenticated the request — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Poisoned `head.sha`/`ref`/`state`/`labels` values can influence downstream review-stack provisioning logic (e.g., label-driven behaviors in `ReopenedHandler`/label handlers) and displayed PR state, creating a foothold for further tenant confusion.

### Likelihood Explanation
Preconditions: a multi-tenant Shipit deployment configured with per-org GitHub apps (`Shipit.github_organizations`/`github_app_config`), where the attacker controls at least one onboarded org's webhook secret (a normal, low-privilege capability — e.g., any org admin who set up their own repo's Shipit webhook). No Shipit session, API token, or GitHub App private key is required; the only requirement is knowledge of one legitimately-configured `webhook_secret`, which the attacker sets themselves when wiring up their own org's webhook. The attack is a single crafted HTTP POST to `/webhooks` with a valid signature and a mismatched `repository.owner.login`/`repository.full_name`, fully repeatable against any repository/PR number known to the attacker.

### Recommendation
In `EditedHandler`, `AssignedHandler`, and all other `PullRequest`/webhook handlers that resolve a `Repository`/`Stack` from `payload.dig('repository', 'full_name')`, cross-validate that `params.repository.full_name` belongs to the same org that authenticated the request (i.e., re-derive/compare owner login from `full_name` against `WebhooksController`'s `repository_owner`, or pass the authenticated org into the handler and require `repository.owner == authenticated_org`) before performing any lookup or `update`. Reject the event (422/ignore) on mismatch.

### Proof of Concept
minitest (analogous to `test/models/shipit/webhooks/handlers/pull_request/edited_handler_test.rb`, extended to the controller layer to exercise `verify_signature`):

```ruby
test "cross-org signature forgery poisons another org's PullRequest via edited event" do
  victim_pr = shipit_pull_requests(:review_stack_review) # belongs to ORG_B's repository/stack
  attacker_org = "org-a" # attacker configures ORG_A's webhook secret themselves

  payload = payload_parsed(:pull_request_opened)
  payload["action"] = "edited"
  payload["number"] = victim_pr.number
  payload["repository"]["owner"]["login"] = attacker_org       # used by verify_signature -> ORG_A secret
  payload["repository"]["full_name"] = "org-b/victim-repo"     # used by EditedHandler to find ORG_B's PR
  payload["pull_request"]["title"] = "PWNED"

  body = payload.to_json
  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", org_a_webhook_secret, body)

  @request.headers["X-Github-Event"] = "pull_request"
  @request.headers["X-Hub-Signature"] = signature

  assert_changes -> { victim_pr.reload.title }, to: "PWNED" do
    post :create, body:, as: :json
  end
  assert_response :ok
end
```

Assertions on both sides of the binding: (1) `verify_signature` succeeds because `repository_owner == "org-a"` matches the secret used to sign; (2) despite that, `victim_pr` (owned by `org-b`, never authenticating this request) is mutated — proving `ORG_A (signer) != ORG_B (mutated record owner)`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-65)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def respond_to_assignee_change?
            %w[assigned unassigned].include?(params.action)
          end

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
```
