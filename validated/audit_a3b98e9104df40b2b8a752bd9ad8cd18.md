### Title
Webhook signature check binds trust to the attacker-controlled `organization`/`repository.owner.login` field, not to the `repository.full_name` handlers act on - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, a value read straight out of the untrusted JSON body (`params.dig('repository','owner','login')` or `organization.login`). The event handlers that actually perform writes (archiving/unarchiving stacks, syncing branches, updating pull requests) independently pick the target `Repository`/`Stack` using a *different* field from the same body: `repository.full_name`. The verified identity (organization used to fetch the signing secret) and the entity mutated (repository resolved via `full_name`) are never checked for consistency.

### Finding Description
`verify_signature` computes: [1](#0-0) 

`repository_owner` is derived purely from the request body: [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config, and `verify_webhook_signature` in `GitHubApp`: [3](#0-2) 

Note `return true unless webhook_secret` — if the resolved organization has no `webhook_secret` configured (a documented/supported config state, see `test/dummy/config/secrets_double_github_app.yml` where `webhook_secret:` is left blank for both `OrgOne` and `OrgTwo`), signature verification is skipped entirely and always passes.

Meanwhile, every handler that performs the actual side effect resolves its target repository from a completely separate field of the same JSON body: [4](#0-3) 

e.g. `PushHandler#process` syncs branches for stacks under `repository.full_name`: [5](#0-4) 

and pull-request handlers archive/unarchive review stacks or update pull request metadata based on `params.repository.full_name`: [6](#0-5) [7](#0-6) 

**Binding that should hold:** `organization used to select/verify the signing secret == owner of the repository whose stacks are mutated by the handler`.

**What actually happens:** the controller verifies against `repository.owner.login` (or top-level `organization.login`), while the handler mutates state for `repository.full_name`. Nothing forces these two values, both attacker-supplied in the same JSON body, to refer to the same repository/organization. If any configured organization in a multi-org Shipit deployment (`Shipit.github_organizations`) has no `webhook_secret` set — a state the codebase explicitly supports (`return true unless webhook_secret`) — an attacker who knows (or guesses) that organization's login can post a forged, unsigned request directly to `/webhooks` with:
- `repository.owner.login` (or `organization.login`) = the secret-less organization → signature check trivially passes,
- `repository.full_name` = a *different*, fully-protected organization's repository whose stacks exist in Shipit.

The handler then acts on that second repository's stacks (unarchiving review stacks, triggering `sync_github`, mutating pull request labels/state) without ever having been validated by that repository's real webhook secret.

### Impact Explanation
This breaks the cross-organization/cross-repository trust boundary the signature check is meant to enforce: unauthenticated writes are performed against a repository's stacks that the attacker was never authorized to push webhooks for. Concretely reachable effects via existing handlers include forcing `Stack#sync_github` (refetching/rewriting deployable commit state) and archiving/unarchiving review stacks or mutating `PullRequest` records for arbitrary tracked repositories — i.e., cross-repository writes performed without the correct organization's credential being checked, satisfying the "Critical: cross-repository writes" bar.

### Likelihood Explanation
Exploitability depends on a specific but supported deployment condition: at least one configured GitHub organization/App entry with `webhook_secret` unset (the repo's own fixture `secrets_double_github_app.yml` demonstrates two orgs configured this way) while other organizations' repositories are also tracked in the same Shipit instance. Given multi-org Shipit installs are an explicit supported feature (`Shipit.github_organizations`, `github_app_config`), and `webhook_secret` is optional per the code path (`return true unless webhook_secret`), this is a realistic, low-effort attack requiring only knowledge of one organization's login name and no credentials.

### Recommendation
Bind the two lookups: resolve the repository/stack for the event using the same organization that was cryptographically verified (e.g., verify `repository.full_name`'s owner segment matches `repository_owner` before dispatching to handlers), and/or require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`). Additionally, handlers should validate that the resolved repository's owner matches the verified organization before performing any mutation.

### Proof of Concept
1. Deploy Shipit with two organizations configured under `secrets.github`: `OrgUnsecured` (no `webhook_secret`) and `OrgTarget` (properly configured, with tracked stacks/repos).
2. POST directly to `/webhooks` (no `X-Hub-Signature` needed) with headers `X-Github-Event: pull_request` and body:
```json
{
  "action": "unlabeled",
  "number": 1,
  "pull_request": { "...": "..." },
  "repository": { "owner": { "login": "OrgUnsecured" }, "full_name": "OrgTarget/protected-repo" },
  "sender": { "login": "attacker" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgUnsecured")`; since that org has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally — the request is accepted despite carrying no valid signature for `OrgTarget`.
4. `UnlabeledHandler` resolves `repository` via `params.repository.full_name` ("OrgTarget/protected-repo") and archives/unarchives the corresponding review stack, mutating state for a repository the attacker never authenticated against.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L49-63)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
