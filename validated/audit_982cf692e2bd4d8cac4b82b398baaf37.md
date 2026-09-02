### Title
Verifier/target field divergence in webhook processing lets a lenient org's (missing) webhook secret authenticate `pull_request` events for a different organization's repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) validates a request using `repository_owner`, which falls back to `params.dig('organization', 'login')` when `repository.owner.login` is absent. [1](#0-0)  The `pull_request` handlers, however, resolve the repository whose state actually gets mutated independently, from `params.repository.full_name`. [2](#0-1)  These two fields are never checked against each other, so if any configured organization has no `webhook_secret` set (a documented/default configuration state), a request "verified" against that organization's app can carry a `repository.full_name` pointing at any other repository, and `ClosedHandler#process` will archive that victim stack. [3](#0-2) 

### Finding Description
The broken invariant, stated as an equality that the code should enforce but does not: `repository_owner` (used to pick the verifying `GitHubApp`) should equal the owner implied by `params.repository.full_name` (used by the handler to select the target `Repository`/`ReviewStack`). In `verify_signature`, `repository_owner` is computed as `params.dig('repository','owner','login') || params.dig('organization','login')`. [1](#0-0)  That value is passed to `Shipit.github(organization: repository_owner)` to obtain a `GitHubApp`, whose `verify_webhook_signature` compares the request's HMAC signature against that org's own `@webhook_secret`; critically, `return true unless webhook_secret` means **any** payload is accepted if that org's secret is unset/blank. [4](#0-3) 

Meanwhile `ClosedHandler` (and the other `pull_request` handlers) resolves the repository to mutate purely from `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, and then calls `review_stack.archive!` on that repository's review stack. [5](#0-4) [6](#0-5)  `repository.owner.login` and `repository.full_name` are independent, attacker-controlled JSON fields in the same request body — nothing forces `full_name`'s owner segment to match `repository_owner`.

Exploit request: omit `repository.owner.login`, include `organization: { login: "<lenient-org>" }` (an org whose Shipit multi-org config has no `webhook_secret` configured — this is the documented default in `config/secrets.development.example.yml` and the multi-org template in `docs/setup.md`), and set `repository: { full_name: "<victim-org>/<victim-repo>" }` plus a valid `pull_request` payload with `action: "closed"`. `X-Github-Event: pull_request` is set, and no valid `X-Hub-Signature` is needed since verification against the lenient org's blank secret always returns `true`.

This bypasses the guards the audit specifically calls out: `verify_signature` only checks the signature against whichever org `repository_owner` resolves to — it never checks that this org matches the repository actually referenced in the payload; `drop_unhandled_event` and `ExplicitParameters` (`requires :repository { requires :full_name, String }`) only validate presence/type, not ownership consistency; there is no `Repository`-to-org binding check anywhere in `ClosedHandler` or `ReviewStackAdapter`.

### Impact Explanation
An attacker who can trigger (or send) a `pull_request` "closed" event that is verified against any organization with no configured `webhook_secret` can archive the `ReviewStack` (deprovision, remove from provisioning queue, mark archived) of any other organization's repository tracked by the same Shipit instance, by simply naming that victim repository in `repository.full_name`. This is a cross-tenant state mutation — a payload verified for one org/repo writes/destroys another repo's active review stack — matching the "Critical: a payload for one repository mutating another's stack" category. It is repeatable against any repository whose full name the attacker knows, as long as at least one configured org's `webhook_secret` is unset.

### Likelihood Explanation
Exploitability is conditioned entirely on Shipit's own configuration: it requires at least one configured GitHub org/app entry in `secrets.github` with a blank/unset `webhook_secret`. The example/development secrets templates ship with `webhook_secret: # nil` by default, and the multi-org documentation in `docs/setup.md` shows per-org secret entries that can independently be left blank, so this is a realistic and even encouraged-by-example misconfiguration rather than a purely theoretical one. Given that precondition, the attacker needs no credentials at all — an unauthenticated `POST /webhooks` request with a crafted JSON body and the `X-Github-Event: pull_request` header suffices; no valid signature, GitHub App key, or Shipit session is required.

### Recommendation
Bind the verifying organization to the actual target repository instead of trusting attacker-controlled `organization.login`/`repository.owner.login` independently of `repository.full_name`: derive `repository_owner` from `repository.full_name`'s owner segment (or require them to match when both are present), and reject events where `organization.login` disagrees with the owner implied by `repository.full_name`. Additionally, treat a missing/blank `webhook_secret` for any configured org as a hard misconfiguration and refuse to skip signature verification silently (`verify_webhook_signature` should not `return true unless webhook_secret` in production).

### Proof of Concept
minitest plan (mirrors existing `test/controllers/webhooks_controller_test.rb` style, add to that file or a new test):
1. Configure two orgs in test secrets (or stub `Shipit.github_app_config`) such that org `"lenient-org"` has `webhook_secret: nil` and org `"victim-org"` has a real `webhook_secret` set.
2. Create fixtures: a `Shipit::Repository` with `full_name: "victim-org/victim-repo"` and an associated `ReviewStack` (via `pull_request` open flow or directly) that is not archived — assert `review_stack.archived?` is `false` before the request (left side of the equality: `repository_owner == "lenient-org"`, `repository.full_name == "victim-org/victim-repo"` — these must differ to prove the divergence).
3. Send `POST :create` with `request.headers['X-Github-Event'] = 'pull_request'`, no (or garbage) `X-Hub-Signature`, and body:
   ```json
   {
     "action": "closed",
     "number": <pr_number>,
     "pull_request": { "id": ..., "number": ..., "url": "...", "title": "...", "state": "closed", "additions": 0, "deletions": 0, "head": { "sha": "...", "ref": "..." }, "user": { "login": "attacker" }, "assignees": [], "labels": [] },
     "repository": { "full_name": "victim-org/victim-repo" },
     "organization": { "login": "lenient-org" },
     "sender": { "login": "attacker" }
   }
   ```
4. Assert `response.status == 200`.
5. Reload the `ReviewStack` for `victim-org/victim-repo` and assert `review_stack.archived? == true` — proving state change attributed to `victim-org` occurred via a signature check that only validated against `lenient-org`'s (absent) secret, violating "A forged webhook cannot cause any state change attributed to a repository/org whose secret did not verify it."

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L33-53)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end
```
