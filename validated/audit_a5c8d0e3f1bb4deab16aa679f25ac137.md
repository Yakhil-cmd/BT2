### Title
Signature verification keyed on `repository.owner.login` while handlers mutate the repository resolved from `repository.full_name` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to check the HMAC against using `repository_owner` (`params.dig('repository','owner','login')`), while `AssignedHandler` (and the other `pull_request` handlers) resolve the actual `Repository`/`Stack` to mutate from a completely independent field, `params.repository.full_name`. Nothing in the controller or in `ExplicitParameters` schemas enforces that these two fields agree.

### Finding Description
The invariant that should hold is: `organization_used_to_verify_signature == owner(repository.full_name)`. In practice the controller computes: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` is looked up purely from `repository.owner.login` (or `organization.login`), and `verify_webhook_signature` is invoked on that org's `GitHubApp` instance: [3](#0-2) 

Critically, `verify_webhook_signature` returns `true` unconditionally when that particular org's config has no `webhook_secret` set (`return true unless webhook_secret`). Shipit explicitly supports a multi-org configuration where each org can independently configure (or omit) `webhook_secret`, as documented and exercised in `test/dummy/config/secrets_double_github_app.yml`, both orgs there having `webhook_secret: # nil`.

Meanwhile the actual repository/stack that gets mutated is resolved independently from `repository.full_name`, not from `repository.owner.login`: [4](#0-3) 

`Shipit::Repository.from_github_repo_name` simply splits `full_name` on `/` and does a DB lookup — it has no relationship to `repository.owner.login` used for signature selection: [5](#0-4) 

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: pull_request`, `action=unassigned`, `repository.owner.login = "NoSecretOrg"` (an org configured in Shipit without a `webhook_secret`) and `repository.full_name = "VictimOrg/victim-repo"` (the real, secret-protected org/repo hosting the target stack). The signature header can be garbage/empty. `verify_signature` resolves `Shipit.github(organization: "NoSecretOrg")`, whose `verify_webhook_signature` trivially returns `true` because that org has no secret configured, so the request passes. `AssignedHandler#process` then resolves `repository` from `full_name` = `VictimOrg/victim-repo`, finds the matching `Shipit::PullRequest` by `number` + `stacks.repositories.id`, and calls `pull_request.update(github_pull_request: params.pull_request)`, persisting attacker-controlled PR state (title, sha, assignees, labels, additions/deletions) against the victim's stack.

Existing guards do not stop this: `verify_signature` only checks the signature against whichever org `repository_owner` names — it never cross-checks that `repository.full_name`'s owner segment matches `repository_owner`. `ExplicitParameters` schemas in the handlers only enforce presence/type of fields, not cross-field consistency. `drop_unhandled_event` and `check_if_ping` don't touch this logic either.

### Impact Explanation
This lets an unauthenticated attacker forge state-mutating webhook events (`pull_request` `assigned`/`unassigned`, and by the identical pattern every other handler that resolves its target via `repository.full_name`, e.g. `ClosedHandler`, `LabeledHandler`, `OpenedHandler`, `ReopenedHandler`, `UnlabeledHandler`, `EditedHandler`) against ANY stack belonging to an org that does have a secret configured, as long as at least one other org configured on the same Shipit instance has no `webhook_secret`. The persisted `PullRequest.github_pull_request` (sha, assignees, labels, additions/deletions, title) drives merge-queue and stack behavior; combined with `bot_login`-driven auto-triggered deploy/merge flows, an attacker can inject false PR metadata (e.g. forged head sha, fabricated labels used for provisioning/merge gating) into the victim stack's persisted record. This is a genuine "payload for one repository mutating another's stack" — matching the Critical impact category — because the org whose secret is checked is not the org whose data is mutated.

### Likelihood Explanation
Preconditions: Shipit must be configured with the multi-org github schema (`github: {OrgA: {...}, OrgB: {...}}`) documented in `docs/setup.md`, and at least one configured org must have no `webhook_secret` set (permitted/likely in dev or partially-onboarded orgs, as shown by the shipped example configs). The attacker does not need to know any secret — only the login of a no-secret org and the `full_name` of the target repository (public information). Cost is a single crafted HTTP POST; the attack is trivially repeatable against any tracked repository under any org with a configured secret, as long as one no-secret org exists in the same deployment.

### Recommendation
Verify the webhook signature using the same organization that the handler will actually use to resolve the target repository (derive both from `repository.full_name`, not `repository.owner.login`/`organization.login`), or explicitly assert `repository.owner.login == full_name.split('/').first` before dispatching, rejecting mismatches with 422. Additionally, do not allow `verify_webhook_signature` to silently return `true` for orgs without a configured secret in production — require `webhook_secret` presence for any org handling webhook traffic (or reject unrecognized/orphan owner logins).

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb`):
1. Configure two orgs via a stubbed `Shipit.secrets`/`Shipit.stubs(:secrets)` mirroring `test/dummy/config/secrets_double_github_app.yml`: `NoSecretOrg` (no `webhook_secret`) and `VictimOrg` (with a `webhook_secret`).
2. Create `shipit_repositories(:victim)` with `owner: "victimorg"`, and a `Shipit::PullRequest` + `Shipit::Stack` under it, with `bot_login` configured for `VictimOrg`.
3. POST to `/webhooks` with `X-Github-Event: pull_request`, body `{ "action": "unassigned", "number": <pr.number>, "pull_request": {...forged sha/title/assignees...}, "repository": {"owner": {"login": "NoSecretOrg"}, "full_name": "victimorg/victim-repo"}, "sender": {"login": "attacker"} }`, with an arbitrary/garbage `X-Hub-Signature`.
4. Assert response is `200 OK` (not `422`), i.e. `Shipit.github(organization: "NoSecretOrg").verify_webhook_signature` returned true despite the bogus signature.
5. Assert `pull_request.reload.github_pull_request` now reflects the attacker's forged payload — proving the write for `VictimOrg`'s stack occurred without ever validating a signature against `VictimOrg`'s `webhook_secret`.
6. Equality check before/after: before, `repository_owner ("NoSecretOrg") != full_name.split('/').first ("victimorg")`; after the fix, the same mismatch should cause a `422` rejection instead of a persisted mutation.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L53-69)
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
