### Title
Webhook signature verification binds the event to the payload's `repository.owner.login`, not the `repository.full_name` the handlers actually write to, enabling cross-repository forged webhook writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify the HMAC signature against using `repository.owner.login` taken directly from the untrusted JSON body, but the individual webhook handlers (e.g. the pull-request handlers) resolve the target `Repository`/`Stack` to mutate using a *different* field of the same body: `repository.full_name`. Because these two fields are never checked for consistency, an attacker who legitimately controls **any** organization/repository onboarded into this Shipit instance (and therefore knows that org's own genuine `webhook_secret`) can forge a payload that authenticates as their own org while pointing `repository.full_name` at a completely different, victim-owned repository/stack. The handler then trusts and writes to the victim's records.

### Finding Description
In `WebhooksController#verify_signature`, the organization used to pick the verification secret comes straight from the request body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns the `GitHubApp` configured for that *owner*, and `verify_webhook_signature` checks the `X-Hub-Signature` header against that organization's own `webhook_secret`: [3](#0-2) 

Once verification succeeds, `WebhooksController#create` dispatches the raw, attacker-controlled JSON `params` to the registered handler for the event type, with no further scoping to the organization that was actually authenticated. Handlers independently resolve which repository/stack to act on using `repository.full_name` — a sibling field of the same payload that was never covered by the signature-selection logic (both fields are attacker-controlled but only `owner.login` participates in choosing the secret used for verification): [4](#0-3) 

`Repository.from_github_repo_name` performs a straightforward owner/name lookup with no cross-check against `repository.owner.login`: [5](#0-4) 

The security invariant the engine relies on is: *"the organization whose secret validated this signature" == "the repository this event is permitted to mutate."* This invariant is never enforced. An attacker who operates their own onboarded GitHub organization/repo (with their own legitimately issued `webhook_secret`) can sign a payload with their own secret, satisfy `verify_signature`, yet set `repository.full_name` (and other repository-scoped fields used deeper in handler logic) to point at an unrelated victim repository tracked by the same Shipit instance.

### Impact Explanation
This breaks the binding between "organization that authenticated" and "repository that is written," directly matching a cross-repository write: an attacker with no relationship to (and no write access on) the victim repository can inject/modify records belonging to that victim's stack (e.g. overwrite `PullRequest#github_pull_request` with attacker-supplied data via the `pull_request/edited` handler). Depending on which handler is targeted, this class of confusion can be leveraged to inject falsified pull-request/commit metadata into a victim stack that Shipit's merge queue and deploy gating logic subsequently trust — an unauthorized cross-repository write into another tenant's data, which is a Critical-severity outcome per this engine's trust model.

### Likelihood Explanation
Exploitation requires only that the attacker control (or be granted) any organization/repository already configured in the same Shipit instance — a routine, low-privilege situation in multi-tenant Shipit deployments where many teams/orgs share one instance. No access to the victim's webhook secret, GitHub App private key, or any `ApiClient` token is needed; the attacker directly POSTs a crafted JSON body signed with their own legitimate secret to the shared `/webhooks` endpoint.

### Recommendation
In `WebhooksController#verify_signature`, do not let the same untrusted field that is used to select the verifying secret be trusted independently by downstream handlers for target resolution. Concretely:
- After verifying the signature for `repository_owner`, enforce that every repository-scoped field consumed by handlers (`repository.full_name`, `organization.login`, etc.) is consistent with `repository_owner` before dispatch, rejecting the event otherwise.
- Alternatively, resolve the target repository/stack once at the controller level (using the same field used for signature verification) and pass that resolved, trusted object into handlers instead of letting each handler independently re-derive it from the raw, unchecked payload.

### Proof of Concept
1. Attacker owns/administers GitHub org `attacker-org`, which is legitimately onboarded to the shared Shipit instance with GitHub App webhook secret `S_attacker` (known to the attacker because they configured the GitHub App webhook for their own org).
2. Victim org `victim-org/victim-repo` is tracked by a different stack in the same Shipit instance.
3. Attacker crafts a `pull_request` webhook JSON body:
```json
{
  "action": "edited",
  "number": 42,
  "pull_request": { "...attacker-controlled fields..." },
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sender": { "login": "attacker-org-bot" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(S_attacker, raw_body)` and POSTs to `/webhooks`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")`, verifies successfully against `S_attacker`.
6. `Shipit::Webhooks.for_event('pull_request')` dispatches to `PullRequest::EditedHandler#process`, which calls `repository` → `Shipit::Repository.from_github_repo_name("victim-org/victim-repo")`, finds the victim's `PullRequest` record, and overwrites it with attacker-supplied `github_pull_request` data — a write to a repository the attacker never authenticated for.

*Note: I was not able to fully verify within available searches whether `push_handler.rb` and `status_handler.rb` follow the identical `full_name`-based lookup pattern (their source was not directly inspected before the tool budget was exhausted); the `pull_request/edited_handler.rb` path above is fully confirmed and sufficient to establish the vulnerability.*

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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-65)
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
