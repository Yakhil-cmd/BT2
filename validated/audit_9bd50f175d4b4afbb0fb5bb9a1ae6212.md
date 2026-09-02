### Title
Cross-organization signature-verification bypass in `WebhooksController#verify_signature` lets a secretless org's webhook mutate another org's `PullRequest` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` used to verify the HMAC signature from `repository_owner`, which falls back to `params.dig('organization','login')` when `repository.owner.login` is absent, while `EditedHandler#repository` independently resolves the *target* repository from `params.repository.full_name`. Because these are two different keys read independently from the same JSON body, an attacker can name a configured-but-secretless organization in the top-level `organization` object while pointing `repository.full_name` at a victim repository belonging to a different, secret-protected organization, causing verification to trivially pass and the victim's `PullRequest` to be mutated.

### Finding Description
The broken binding: `organization` whose `webhook_secret` gated the accepted request **should equal** `repository.owner` of the `Shipit::Repository` that the handler mutates. The code lets these diverge.

- `verify_signature` picks the app via `repository_owner`: [1](#0-0) [2](#0-1) 

- `GitHubApp#verify_webhook_signature` trivially returns `true` when the selected org has no configured `webhook_secret`: [3](#0-2) 

- `EditedHandler#repository` resolves the mutated repository from a completely independent key, `params.repository.full_name`, and only requires that single field in its `ExplicitParameters` schema (no `repository.owner.login` requirement): [4](#0-3) [5](#0-4) 

- The resolved repository is then used to look up and mutate the victim's `PullRequest`: [6](#0-5) 

**Exploit flow**: Assume two configured GitHub orgs (confirmed possible by the multi-org config schema, e.g. `test/dummy/config/secrets_double_github_app.yml`), `shopify` (has `webhook_secret`) and an attacker-known org, e.g. `looseorg` (no `webhook_secret`). The attacker POSTs to `/webhooks` with header `X-Github-Event: pull_request` and a body:
```json
{
  "action": "edited",
  "number": <victim PR number>,
  "pull_request": { ... attacker-controlled fields ... },
  "repository": { "full_name": "shopify/rails" },
  "organization": { "login": "looseorg" },
  "sender": { "login": "attacker" }
}
```
`repository_owner` returns `nil` (no `repository.owner.login` in the payload) and falls back to `organization.login` = `"looseorg"`. `verify_signature` calls `Shipit.github(organization: "looseorg")`, whose `webhook_secret` is unset, so `verify_webhook_signature` returns `true` unconditionally — no HMAC check occurs at all. The request proceeds to `EditedHandler`, which reads `params.repository.full_name` = `"shopify/rails"`, resolves the real `Shipit::Repository` owned by `shopify`, finds the matching `Shipit::PullRequest`, and calls `pull_request.update(github_pull_request: params.pull_request)` with fully attacker-controlled content (title, labels, assignees, additions/deletions, head sha/ref, etc.) — none of it authenticated by `shopify`'s secret.

Existing guards don't help: `drop_unhandled_event` only checks handler registration for the event type, not payload contents; `ExplicitParameters` schema for `EditedHandler` requires only `repository.full_name`, not `owner.login`; `GithubOrganizationUnknown` only triggers if the org name is unrecognized — here it's a real, configured org, just one without a secret.

### Impact Explanation
An unauthenticated internet attacker can overwrite `PullRequest` metadata belonging to any repository under any *other*, secret-protected organization, as long as the Shipit deployment also hosts at least one org without a configured `webhook_secret`. This is a genuine "payload for one repository mutating another's stack/record" scenario — the request is verified against one tenant's (non-existent) secret while writing to another tenant's data. It is fully repeatable against any `PullRequest` in any stack whose repository full name is known/guessable (`owner/repo`), matching the Critical impact category.

### Likelihood Explanation
Requires the operator to run multiple GitHub App configs where at least one organization has no `webhook_secret` set (a supported and documented configuration state per `lib/shipit.rb#github_app_config` and the example secrets files) alongside at least one org that does set a secret. Given that precondition, the attack costs nothing: no credentials, no session, just one crafted HTTP POST with a known/guessable `owner/repo` and PR number. It is trivially repeatable and requires no interaction with GitHub at all.

### Recommendation
Verify the webhook signature using the `GitHubApp` for the organization that actually owns the *target* repository referenced by the payload (i.e., derive `repository_owner` from the same `repository.full_name`/`repository.owner.login` value that handlers use to resolve `Shipit::Repository`, not from an independent `organization.login` fallback), or alternatively require repository-derived owner to match the organization used for verification before dispatching to handlers, and reject payloads where they diverge. Consider also always requiring a non-blank `webhook_secret` for any configured organization (removing the `return true unless webhook_secret` bypass in `GitHubApp#verify_webhook_signature`) so a secretless org can never be used to authenticate arbitrary payloads.

### Proof of Concept
minitest under `test/controllers/webhooks_controller_test.rb` (conceptual, not to be placed per repo rules but describing the assertion):
1. Configure two orgs in test secrets: `shopify` (with `webhook_secret: "s3cr3t"`) and `looseorg` (no `webhook_secret`).
2. Create `shipit_stacks(:shopify_rails)` under repository `owner: 'shopify', name: 'rails'`, and a `Shipit::PullRequest` `number: 42` on that stack with `title: "original"`.
3. POST to `/webhooks` with `X-Github-Event: pull_request`, no `X-Hub-Signature` header, and body:
```ruby
{
  action: 'edited',
  number: 42,
  pull_request: { id: 1, number: 42, url: 'x', title: 'PWNED', state: 'open',
                   additions: 0, deletions: 0, head: { sha: 'a', ref: 'b' },
                   user: { login: 'attacker' }, assignees: [], labels: [] },
  repository: { full_name: 'shopify/rails' },
  organization: { login: 'looseorg' },
  sender: { login: 'attacker' }
}.to_json
```
4. Assert `response.status == 200` (verification bypassed) and assert the victim PR's `title`/`github_pull_request['title']` now equals `'PWNED'` — i.e., `pull_request.reload.github_pull_request['title'] == 'PWNED'` — demonstrating the equality `organization_verified ('looseorg') != repository_owner_mutated ('shopify')` was violated and exploited.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-61)
```ruby
          def process
            return unless respond_to_pull_request_edited?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L63-65)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```
