### Title
`pull_request` `edited` webhook authenticated against a no-secret org can mutate a different org's `PullRequest` record - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the secret to verify against) using `repository_owner`, which is read from `params.dig('repository','owner','login')` [1](#0-0) . `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that org has no `webhook_secret` configured: `return true unless webhook_secret` [2](#0-1) . Meanwhile `EditedHandler` resolves and mutates a `PullRequest` using a completely independent field, `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name` [3](#0-2) . Because these two values are never required to match, an attacker can pick an org for `repository.owner.login` that has no `webhook_secret` set (trivially passing verification), while `repository.full_name` points at a genuine, secret-protected repository/stack whose `PullRequest` gets overwritten.

### Finding Description
The broken invariant should be: `repository_owner used to verify the signature == owner(params.repository.full_name) used to resolve the mutated record`. In the code, these are two unrelated reads of `params`:

- Verification org: `repository_owner` = `params.dig('repository','owner','login')` (or `params.dig('organization','login')`) [4](#0-3) .
- Mutation target: `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, which splits `full_name` on `/` to get `repo_owner`/`repo_name` and does `find_by(owner:, name:)` [5](#0-4) .

Nothing in `WebhooksController#create` or `EditedHandler#process` cross-checks that `owner.login` and the owner segment of `full_name` refer to the same organization/repository. GitHub's real webhook payloads always keep these consistent, but this engine's own verification step does not enforce it — it simply uses whichever `GitHubApp` instance `Shipit.github(organization: repository_owner)` returns for the *owner* field, and if that instance has no `webhook_secret` configured, `verify_webhook_signature` short-circuits to `true` for *any* body, regardless of signature header content [6](#0-5) .

Exploit flow:
1. Attacker identifies (or registers) an org `A` that is present in Shipit's GitHub configuration but has no `webhook_secret` set (or is entirely unconfigured, triggering `GithubOrganizationUnknown`/head 422 — so they must pick a *configured-but-secretless* org for the bypass to succeed rather than fail with 422).
2. Attacker crafts a `pull_request` `action=edited` JSON payload with `repository.owner.login = "A"` (no secret) but `repository.full_name = "victim-org/victim-repo"` (the real, secret-protected target stack that has `blocking_statuses` configured).
3. `verify_signature` computes `Shipit.github(organization: "A")`, whose `verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is blank for `A` [2](#0-1) . No valid `X-Hub-Signature` is required.
4. `Shipit::Webhooks.for_event('pull_request').each { |handler| handler.call(params) }` dispatches to `EditedHandler`, which loads `repository` from `params.repository.full_name = "victim-org/victim-repo"` and updates the persisted `Shipit::PullRequest` matching that repository's stack with `params.pull_request` (attacker-controlled title, labels, additions/deletions, assignees, head sha/ref, state) [7](#0-6) .

Existing guards do not catch this: `drop_unhandled_event` only checks the event type exists, `verify_signature` verifies against the wrong (attacker-chosen) org, and `ExplicitParameters` (`params do ... end` in `EditedHandler`) only validates payload shape, not the owner/full_name relationship.

### Impact Explanation
This lets an unprivileged internet requester overwrite a victim stack's `PullRequest` record (`github_pull_request` field) for a repository they never authenticated against and do not own, purely by choosing a different, secret-less organization name in `repository.owner.login`. Since the victim stack has `blocking_statuses` configured, any downstream logic keyed off the mutated `PullRequest` state can be forced into a different blocked/unblocked state, gating or ungating deploys for a repository the attacker never proved control over. This is a cross-tenant state-mutation matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." It is repeatable against any victim stack whose full repo name the attacker knows, as long as some other configured org lacks a `webhook_secret`.

### Likelihood Explanation
Preconditions: Shipit must have at least one organization configured (present in `Shipit.github_configuration`/similar) without a `webhook_secret` set, so `Shipit.github(organization: "A")` resolves without raising `GithubOrganizationUnknown` and returns a `GitHubApp` whose `verify_webhook_signature` short-circuits `true`. This is plausible in real deployments (e.g., demo/staging orgs, or orgs onboarded before secrets were rotated in). No authentication, session, or API token is needed — this is the unauthenticated `POST /webhooks` endpoint. Attacker cost is a single crafted HTTP POST; fully repeatable and automatable against any victim repo/stack full name known to the attacker.

### Recommendation
Enforce that the owner segment of `params.repository.full_name` matches `repository_owner` used for signature verification before dispatching to handlers (reject with 422 on mismatch). Additionally, do not treat a missing `webhook_secret` as an automatic pass — either require every configured organization to have a `webhook_secret`, or refuse to process events for orgs without one instead of silently accepting unsigned payloads.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`, out-of-scope to write but described for reproduction):
1. Configure two orgs in test config: `"no-secret-org"` (no `webhook_secret`) and `"victim-org"` (has `webhook_secret` set, e.g. `"secret"`).
2. Create `victim-org/victim-repo` `Repository`, a `Stack` with `blocking_statuses` set, and a `PullRequest` (number 42) with known `github_pull_request` state, e.g. `title: "original"`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, **no valid** `X-Hub-Signature` for `victim-org`'s secret (e.g., omit header or use garbage), and body:
   ```json
   {
     "action": "edited",
     "number": 42,
     "pull_request": { ... "title": "PWNED", ... },
     "repository": { "owner": { "login": "no-secret-org" }, "full_name": "victim-org/victim-repo" },
     "sender": { "login": "attacker" }
   }
   ```
4. Assert response is `200 OK` (not `422`), proving `verify_signature` passed despite no valid signature for `victim-org`.
5. Reload the `PullRequest` for `victim-org/victim-repo`#42 and assert `pull_request.github_pull_request['title'] == "PWNED"`, proving the victim stack's `PullRequest` (belonging to the org that actually has a secret and was never authenticated) was mutated by a payload verified under an unrelated, secret-less org.
6. Equality-before check: `pull_request.github_pull_request['title'] == "original"` before the request; equality-after check: it now equals `"PWNED"` — the binding "only the authenticating org's repo may be mutated" is broken.

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
