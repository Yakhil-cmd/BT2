### Title
Webhook signature verified against the payload-declared organization while repository/stack actions are dispatched using a different payload-declared repository field, enabling cross-repository writes - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
The reported bug class is a **binding break between the entity that is authenticated/verified and the entity that is actually acted upon**. In `AuraLocker.sol` a locker's identity (EOA vs. contract) was never checked, so voting power accrued to whichever entity called `lock`, decoupling the "who is trusted to lock" assumption from "who actually locks." The same class of bug exists in Shipit's webhook pipeline: `WebhooksController#verify_signature` authenticates the delivery against the **organization** named in the untrusted JSON body (`repository.owner.login` / `organization.login`), but the event **handlers** (`Shipit::Webhooks::Handlers::Handler#repository_name`, and every handler built on top of it, e.g. `PushHandler`, `ClosedHandler`) resolve the **repository/stack to mutate** from a *different* field of that same untrusted body: `repository.full_name`.

### Finding Description
`WebhooksController#verify_signature` picks the webhook secret to validate the HMAC using only the org login pulled straight out of the JSON payload: [1](#0-0) 

That verification proves only that *some* entity holding the webhook secret for `repository_owner` (an org that has installed the Shipit GitHub App) produced a valid HMAC over the raw body — it says nothing about the `repository.full_name` field that the handlers subsequently trust to decide **which** `Repository`/`Stack`/`Commit` to mutate: [2](#0-1) 

Because GitHub always sets `repository.owner.login` and `repository.full_name`'s owner segment consistently for real deliveries, this mismatch is invisible under normal operation — but nothing in the code enforces that `repository.full_name.split('/').first == repository_owner`. An attacker who legitimately controls (or has been granted admin of) *any* GitHub organization that has the Shipit GitHub App installed knows that organization's own `webhook_secret` (it is configured per-org for the app installation, e.g. via GitHub's webhook secret field, which org admins can see/rotate). Using that valid secret, the attacker can sign an arbitrary JSON body where `repository.owner.login` (and/or `organization.login`) is set to *their own, verifiable* org, while `repository.full_name` is forged to name a completely different, victim repository already tracked by the target Shipit instance (e.g. `victim-org/victim-repo`).

Concretely:
- `PushHandler` uses `repository_name` (i.e. the forged `full_name`) to look up `Repository.from_github_repo_name` and calls `stack.sync_github(expected_head_sha:)` on the victim's stacks: [3](#0-2) 
- `ClosedHandler` (pull_request `closed` event) resolves the repository the same way and calls `review_stack.archive!`, which deprovisions/archives a victim review stack: [4](#0-3) 
- `StatusHandler` blindly matches `Commit.where(sha: params.sha)` across the whole database, with no repository scoping at all, and writes a commit status record that can affect deploy-gating logic for any stack whose commit shares that sha: [5](#0-4) 

This is exactly the "organization that authenticated versus the repository that is written" binding break described in the analog rules: `verify_signature` proves *organization A* sent the request; the handlers then act on *repository/stack B*, with no check that A and B agree.

### Impact Explanation
An attacker who administers any GitHub organization onboarded to a shared/multi-tenant Shipit instance (a common deployment pattern — Shipit is explicitly designed to serve many orgs/repos from one instance) can forge signed webhook deliveries that are cryptographically valid for their own org but declare an arbitrary victim `repository.full_name`. This lets them:
- Trigger `GithubSyncJob` (`sync_github`) against a victim stack, forcing Shipit to re-sync/queue deploy state at an attacker-chosen `expected_head_sha`.
- Archive or otherwise mutate a victim's `ReviewStack` (deprovisioning infrastructure) via the `pull_request` `closed` handler.
- Inject fabricated commit statuses onto arbitrary commits shared across repositories via `StatusHandler`, which can unblock or gate deploy pipelines that key off commit status.

This is a cross-repository/cross-tenant write achieved purely by crafting a JSON body and computing an HMAC with a secret the attacker legitimately possesses for an unrelated org — no privileged Shipit account, `ApiClient` token, or GitHub App private key is required. This matches the "cross-repository writes / unauthorized deploy" Critical impact bucket.

### Likelihood Explanation
Requires the attacker to control (or be an admin/member with app-config visibility of) at least one GitHub organization that is legitimately configured in the target Shipit instance (multi-tenant deployments are the documented, intended use case per `docs/setup.md`), and to know that org's own webhook secret — both readily achievable by a self-service org owner, with no code execution, no stolen tokens, and no reliance on host misconfiguration.

### Recommendation
In `WebhooksController#verify_signature` and/or `Handler#repository_name`, cross-validate that the organization used to select the HMAC secret matches the owner segment of `repository.full_name` (and `organization.login` when present) before dispatching to handlers; reject the delivery otherwise. Additionally, scope `StatusHandler`'s `Commit.where(sha:)` lookup by the verified repository rather than matching sha globally.

### Proof of Concept
1. Attacker owns GitHub org `attacker-org`, which is installed as a Shipit GitHub App and has webhook secret `S` (known to the attacker as org admin).
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } }
}
```
3. Attacker computes `sha1=` HMAC of the raw body using secret `S` and sends it as `X-Hub-Signature`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and successfully verifies the signature against `S`. [1](#0-0) 
5. `PushHandler#process` resolves `repository_name` from `repository.full_name` = `"victim-org/victim-repo"`, unrelated to the verified `attacker-org`, and calls `stack.sync_github(expected_head_sha: "deadbeef")` on the victim's stacks. [3](#0-2)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-36)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
