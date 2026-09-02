### Title
Cross-organization webhook forgery bypasses repository binding, allowing commit-status/stack forgery — (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a signature against by reading the `repository.owner.login` (or `organization.login`) field from the **same unauthenticated payload** it is about to verify. Once the signature matches, the payload is dispatched to handlers that resolve the *actual* target (repository/stack/commit) using **different, independently-controlled fields** (`repository.full_name`, or, in the case of `StatusHandler`, only the raw `sha` with no repository scoping at all). Nothing enforces that the organization whose secret validated the request is the organization that owns the repository/commit the handler subsequently mutates.

### Finding Description
Signature verification: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the attacker-supplied JSON body (`params.dig('repository','owner','login')`), and `Shipit.github(organization: repository_owner)` looks up the matching GitHub App config (Shipit explicitly supports multiple, independently configured GitHub Apps/orgs — see `docs/setup.md` "Using Multiple Github Applications"). The HMAC is computed over `request.raw_post`, i.e. the whole body, using that organization's `webhook_secret`.

Handler dispatch then resolves *what gets acted on* using unrelated fields of the same attacker-controlled body: [3](#0-2) 

`repository_name` uses `repository.full_name`, which is a separate JSON field from `repository.owner.login` used for signature-org selection — the two are never cross-checked. Worse, `StatusHandler` doesn't even use the repository field: [4](#0-3) 

`Commit.where(sha: params.sha)` matches by commit SHA globally across the whole Shipit instance, with no repository/stack scoping whatsoever.

This is the same class of bug as the report: a field that is authenticated (the organization used to pick the signing secret) is not the field that is actually acted upon (the repository/commit the handler mutates), i.e. **"an organization that authenticated versus the repository that is written."** Any attacker who legitimately controls a GitHub App/webhook secret for *one* organization configured in this Shipit instance (a normal, supported multi-org deployment per `docs/setup.md`) can:
1. Set `repository.owner.login` to their own organization (so `verify_signature` validates using a secret they know), while
2. Setting `repository.full_name` (for push/PR/check_suite handlers) or `sha` (for `StatusHandler`) to point at a target belonging to a completely different, victim organization's stack/commit tracked by the same Shipit instance.

The signature check passes (it's mathematically valid for the attacker's own org secret), and the handler blindly acts on the victim's data.

### Impact Explanation
Highest-impact concrete path is `StatusHandler`: an attacker who controls one configured org's webhook secret can forge a `status` event with an arbitrary `sha` belonging to any commit tracked by the Shipit instance (not restricted to the org they authenticated as) and set `state: success` with a fabricated `context`. `create_status_from_github!` persists this as a real commit status, which per `app/models/shipit/deploy_spec.rb` / `app/models/shipit/status/group.rb` / `app/models/shipit/commit_checks.rb` feeds into deploy-safety and "required status" checks. This can satisfy deploy-gating requirements for a commit the attacker never had access to, enabling an **unauthorized deploy** on a victim stack — matching the Critical impact criterion "an unauthorized deploy, rollback or merge." Push/PR/check_suite handlers additionally allow forcing sync/resync and check-run refresh jobs against arbitrary victim stacks cross-org.

### Likelihood Explanation
Requires the deployment to use Shipit's documented multi-org GitHub App feature (explicitly supported and documented) and for the attacker to legitimately control one configured organization's app/webhook secret while a victim organization's stacks/commits are tracked in the same instance — a realistic scenario for shared/self-service Shipit installs. No `ApiClient` token, session, or repository write access to the victim org is required; only knowledge of the attacker's own org's webhook secret, which they legitimately possess as that org's GitHub App owner.

### Recommendation
After verifying the HMAC, re-derive the organization from the resolved target (e.g., from the `Repository` record matched via `full_name`, or from the `Stack`/`Commit`'s own `Repository#owner`) and assert it equals the organization whose secret validated the signature, rejecting the request otherwise. `StatusHandler` in particular must scope its `Commit` lookup by the repository resolved from the verified organization, not by `sha` alone.

### Proof of Concept
1. Configure Shipit with two GitHub orgs per `docs/setup.md` multi-app setup: `attacker-org` (secret known to attacker, its real owner) and `victim-org` (tracks stack/commit `abc123`).
2. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, body:
```json
{"sha":"abc123","state":"success","context":"ci/required-check","repository":{"owner":{"login":"attacker-org"}}}
```
signed with `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org.webhook_secret, raw_body)>` — a signature the attacker can legitimately compute.
3. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature [1](#0-0) .
4. `StatusHandler#process` matches `Commit.where(sha: "abc123")` — the victim's commit — and writes a forged passing status [4](#0-3) , potentially unblocking deploy checks on `victim-org`'s stack despite the attacker never being authenticated for or authorized on that organization.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
