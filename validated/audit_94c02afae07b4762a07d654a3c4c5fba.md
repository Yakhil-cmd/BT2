### Title
Webhook signature verification authenticates the claimed organization but handlers mutate commits/stacks by attacker-controlled fields never bound to that organization - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to validate a delivery based on `repository_owner`, a value read straight out of the unauthenticated JSON body, and only proves the raw body was signed by *some* configured GitHub organization's `webhook_secret`. It does not prove that the data inside the body (the commit `sha` a status applies to, or the `repository.full_name` used to resolve stacks) actually belongs to that organization. `Handlers::StatusHandler` ignores repository/organization entirely and updates `Commit.where(sha: params.sha)` for any matching commit in the whole database, while `Handlers::PushHandler` (via `Handler#repository_name`) resolves the target `Stack` purely from `repository.full_name`, an independent field of the same signed body. This mirrors the analog rule about "an organization that authenticated versus the repository that is written": the equality `organization authenticated by signature == organization owning the repository/commit acted upon` is never enforced.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb#repository_owner` extracts the verifying organization from the untrusted payload: [1](#0-0) 

That value is used only to select which `GitHubApp` (and thus which `webhook_secret`) is used to HMAC-verify the raw body: [2](#0-1) 

Successful verification therefore means only "this exact byte stream was signed with organization X's secret" - it says nothing about whether the repository/commit data embedded in that same byte stream actually belongs to organization X. Any GitHub organization/App registered in Shipit's multi-tenant `github` config (`Shipit.github(organization:)`) has its own independent `webhook_secret` (see `test/dummy/config/secrets_double_github_app.yml`), and any user who legitimately administers such an organization/repo in GitHub can freely craft and sign arbitrary JSON with that organization's secret (it is delivered by GitHub itself, or can be replayed/forged manually since the attacker holds the secret for their own org).

Downstream, `Handlers::StatusHandler#process` never checks organization or repository at all - it blindly updates any commit matching the attacker-chosen `sha`: [3](#0-2) 

and `Handlers::Handler#stacks`/`#repository_name`, used by `PushHandler`, resolve the acted-upon `Stack` from `repository.full_name`, a field of the same payload that is independent from the `repository_owner` field used to select the verifying secret: [4](#0-3) [5](#0-4) 

So an attacker who controls organization `Attacker` (registered in Shipit with its own `webhook_secret`) can sign a `status` (or `push`) event payload with `Attacker`'s secret while setting `sha` to a commit sha belonging to a victim stack/repository tracked under a completely different organization, and Shipit will accept and apply it, because the controller's authentication step and the handler's target-resolution step consult disjoint, unverified fields of the same JSON body.

### Impact Explanation
`Commit#create_status_from_github!` (driven by `StatusHandler`) writes arbitrary CI/status records for any commit sha in the system. Shipit's deploy safety checks rely on required commit statuses (`ci.require` in `shipit.yml`) to gate whether a commit is deployable. By forging a `status` webhook signed with an organization/secret the attacker legitimately controls, but targeting the `sha` of a victim's pending/unreviewed commit, the attacker can fabricate a passing status for a required CI context on a commit they do not control, defeating the deploy-safety check and enabling an **unauthorized deploy** of that commit through the normal Shipit deploy flow - one of the explicitly accepted Critical impacts.

### Likelihood Explanation
The only prerequisite is that the attacker administers (or has push access to configure a webhook for) any single GitHub organization/App that is registered in Shipit's `github` config - not the victim's organization or repository, and no Shipit session/API token/GITHUB_TOKEN/`api_clients_secret` is needed. Shipit installations that serve multiple organizations (as documented via `Shipit.github(organization:)` / multiple `github_app` blocks) are the realistic deployment shape this engine supports, making the attacker-controlled organization readily obtainable while the victim commit sha can be observed via Shipit's own public/authenticated UI or GitHub.

### Recommendation
- In `WebhooksController`, after signature verification, re-derive the organization strictly from the verified `repository_owner`/`organization.login` and require that every handler validate that the repository/commit/stack it is about to mutate actually belongs to that same organization (or to a `Stack`/`Repository` record whose registered organization matches).
- In `Handlers::StatusHandler#process`, scope the `Commit` lookup by the repository declared in the payload and enforce that this repository's organization matches the one that authenticated the signature (e.g. via `stacks` from `Handler`, joined with `Commit`, instead of a global `Commit.where(sha:)`).
- Reject payloads where `repository.owner.login`/`organization.login` (used to pick the verifying secret) doesn't match the organization owning `repository.full_name`.

### Proof of Concept
1. Attacker registers/owns GitHub organization `attacker-org`, which is configured in Shipit's `github` settings with its own `webhook_secret` (`S_attacker`), independent from the victim organization `victim-org`.
2. Attacker observes (via Shipit's UI, which is often readable) the `sha` of a pending commit on `victim-org/victim-repo` stack that is missing a required CI status (e.g. `ci: { require: [ci/tests] }`).
3. Attacker crafts a `status` webhook JSON body:
```json
{
  "sha": "<victim-pending-commit-sha>",
  "state": "success",
  "context": "ci/tests",
  "repository": {"full_name": "attacker-org/some-repo", "owner": {"login": "attacker-org"}}
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(S_attacker, body)` and POSTs it to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org` from the body, fetches `Shipit.github(organization: 'attacker-org')`, and successfully verifies the signature against `S_attacker` - even though the `sha` inside the body belongs to `victim-org/victim-repo`.
6. `StatusHandler#process` executes `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }`, applying the forged "success" status to the victim's commit regardless of which organization/repository it actually belongs to, potentially satisfying `ci.require` and enabling an unauthorized deploy of that commit.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
