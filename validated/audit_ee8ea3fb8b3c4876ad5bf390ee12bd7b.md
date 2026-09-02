### Title
Webhook Signature Verified Against a Different Organization Than the One Whose Stacks Are Mutated - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController` selects which GitHub App/organization config (and therefore which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` (or `organization.login`) in the *unverified* JSON body, while every `Webhooks::Handlers::Handler` subclass resolves the actual `Repository`/`Stack` to act on from a *different* field of the same unverified body: `repository.full_name`. An attacker who can produce a validly-signed payload for any one configured GitHub organization (including one with no `webhook_secret` set, which is explicitly optional per the setup docs) can set `repository.full_name` to point at a completely different, victim-tracked repository, causing Shipit to process the event as if it legitimately originated from that victim repository.

### Finding Description
Signature verification and target resolution use two different, attacker-controlled fields of the same raw JSON payload:

- Verification org is derived here: `repository_owner` is read from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), and used to select the `GitHubApp` (and its `webhook_secret`) via `Shipit.github(organization: repository_owner)`: [1](#0-0) [2](#0-1) 

- `verify_webhook_signature` trivially returns `true` when the selected org's `webhook_secret` is blank (a supported, "optional" configuration per the setup docs), and otherwise HMACs against that org's own secret only: [3](#0-2) 

- The actual write target is resolved independently, from `repository.full_name`, inside the base handler class shared by all event handlers (push, status, check_suite, membership, pull_request, etc.): [4](#0-3) 

- `Repository.from_github_repo_name` derives the owner purely by splitting `full_name`, with no cross-check against the org used for signature verification: [5](#0-4) 

The binding that should hold is: `organization authenticated by the signature == organization that owns the repository being mutated`. Because the controller authenticates against `repository.owner.login`/`organization.login` while every handler mutates state keyed on `repository.full_name`, these two attacker-supplied strings can diverge freely within a single payload, breaking the binding.

**Before the attack (intended flow):** GitHub sends a webhook for `victim-org/victim-repo`; `repository.owner.login == "victim-org"`, `repository.full_name == "victim-org/victim-repo"`; signature is checked against `victim-org`'s `webhook_secret`; only GitHub (holder of that secret) can produce a valid signature, and the event affects only `victim-org` stacks.

**After the attack:** Attacker controls (or exploits the absent secret of) `attacker-org`. They submit `X-Hub-Signature` valid for `attacker-org`, but set `repository.owner.login`/`organization.login = "attacker-org"` (to pass `verify_signature`) and `repository.full_name = "victim-org/victim-repo"` (to select the victim's tracked repository/stack in the handler). `verify_signature` passes because it only checks the `attacker-org` secret; `PushHandler`/`StatusHandler`/etc. then act on `victim-org/victim-repo`'s actual `Stack`/`Commit` records.

### Impact Explanation
This crosses a repository-boundary trust check without any legitimate credential for the targeted repository, matching the "Critical - cross-repository writes / unauthorized deploy, rollback or merge" category. Concretely:
- A forged `status` event (as exercised in `test/controllers/webhooks_controller_test.rb`, `":state create a Status for the specific commit"`) can inject a fabricated `Status` on a real commit belonging to a repository the attacker doesn't control, which feeds into Shipit's CI-gating/merge-queue logic used to decide whether a pull request or deploy is safe to proceed — enabling an unauthorized merge or deploy on a repository the attacker has no access to.
- A forged `push` event can trigger `GithubSyncJob` against the victim stack, and `membership`/other events can mutate `Team`/`User`/`Membership` records tied to the victim org, all while authenticated only against an unrelated (or secret-less) organization.

### Likelihood Explanation
Exploitability depends on the attacker being able to produce a valid signature for *some* organization configured in the Shipit instance — trivial if that organization has no `webhook_secret` configured (explicitly optional in `docs/setup.md`), or otherwise requires knowledge of that one org's secret (e.g. if the attacker's own org/app is also onboarded to the same Shipit instance, which is a common multi-tenant setup as shown by `config/secrets.development.shopify.yml` listing multiple orgs). No Shipit session, `ApiClient` token, or GitHub write access to the victim repository is required — only the ability to reach the public `/webhooks` endpoint and sign a payload for one tracked-but-differently-owned organization.

### Recommendation
Bind the two fields together before trusting either: after resolving `repository_owner` for signature verification, re-derive the acting repository owner from the same `repository.owner.login`/`organization.login` value (not from `repository.full_name`) inside `Webhooks::Handlers::Handler#repository_name`/`#stacks`, or explicitly assert that `repository.full_name.split('/').first == repository_owner` before dispatching to handlers, rejecting the payload otherwise.

### Proof of Concept
1. Shipit is configured with two GitHub orgs: `victim-org` (has `webhook_secret` set, owns tracked `victim-org/victim-repo`) and `attacker-org` (attacker controls the app/webhook secret, or it has no `webhook_secret` configured).
2. Attacker crafts a `status` (or `push`) webhook JSON body with:
   - `organization.login` / `repository.owner.login` = `"attacker-org"`
   - `repository.full_name` = `"victim-org/victim-repo"`
   - `sha` = a real commit sha belonging to a `victim-org/victim-repo` stack, `state` = `"success"`
3. Attacker computes `X-Hub-Signature: sha1=<HMAC(attacker-org secret, body)>` (or omits it entirely if `attacker-org` has no secret, since `verify_webhook_signature` returns `true` for blank secrets — see `lib/shipit/github_app.rb:76-77`).
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and passes verification.
5. `Shipit::Webhooks.for_event('status').each { |handler| handler.call(params) }` runs the status handler, which resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and updates the real `Status` for the given commit — an action fully attributed to `victim-org/victim-repo` despite being authenticated only against `attacker-org`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
