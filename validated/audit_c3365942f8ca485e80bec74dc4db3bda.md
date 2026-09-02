### Title
Cross-tenant webhook confusion: signature verified against `repository.owner.login` but stacks mutated via independently-controlled `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify against using `repository_owner`, which is read from the same untrusted JSON body (`params.dig('repository', 'owner', 'login')`) as `repository.full_name`, the field `Handler#stacks`/`#repository_name` later use to look up and mutate a `Repository`'s stacks. Because these two fields are independent, attacker-controlled strings within one JSON payload the attacker fully crafts, an attacker who owns/administers their own onboarded organization (and thus legitimately knows its `webhook_secret`) can sign a payload where `repository.owner.login` = their own org (so verification passes) while `repository.full_name` = `victim-org/victim-repo`, causing writes against the victim's stack.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces: `payload.dig('repository','owner','login') == payload.dig('repository','full_name').split('/').first`. In a genuine GitHub-originated webhook this is always true because GitHub itself populates both fields consistently. But `POST /webhooks` is reachable directly by any internet client — the request only needs a valid `X-Hub-Signature` header computed over the raw body with *some* organization's `webhook_secret* [1](#0-0) . The controller resolves which secret to use purely from the attacker-suppliable `repository_owner` helper: [2](#0-1) .

Handler#stacks, run for every registered handler on `create`, then re-parses the exact same JSON body's `repository.full_name` field — not the already-verified `repository_owner` — to resolve which `Repository`/`Stack` records to act on: [3](#0-2) . `Repository.from_github_repo_name` splits on `/` and does a plain `find_by(owner:, name:)` with no ownership check tying it back to the verified signature's organization: [4](#0-3) .

Exploit flow: attacker onboards/owns organization `attacker-org` on Shipit (a normal, unprivileged, self-service action — they legitimately know `attacker-org`'s `webhook_secret` because they configured the GitHub App webhook themselves). They then POST directly to `/webhooks` with `X-Github-Event: status` (or `push`), a JSON body where `repository.owner.login = "attacker-org"` but `repository.full_name = "victim-org/victim-repo"`, HMAC-signed with `attacker-org`'s `webhook_secret`. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature via `GitHubApp#verify_webhook_signature`: [5](#0-4) . The relevant status/push handler then calls `Handler#stacks`, which resolves `victim-org/victim-repo`'s real `Repository` row and its `Stack`s, and creates/mutates `Commit`/`Status` (or triggers deploy-relevant state) for the victim's stacks, entirely under a signature that authenticated a different organization.

None of the existing guards catch this: `drop_unhandled_event` and `check_if_ping` only gate on event type; the `ExplicitParameters` schema in each handler validates shape/presence of fields, not cross-field consistency between `owner.login` and `full_name`; there is no `force_github_authentication`/`User#authorized?`/`require_permission!` check anywhere in this unauthenticated webhook path, since webhooks are meant to be verified purely by HMAC signature — but that verification is bound to the wrong field.

### Impact Explanation
A payload signed with organization A's webhook secret can create `Commit`/`Status` rows (and feed into deploy-triggering logic, depending on which handler fires, e.g. status/push handlers) under organization B's `Stack`, without B's secret ever being involved. This is a cross-tenant, cross-repository write on infrastructure the attacker does not own or control, matching the "payload for one repository mutating another's stack, commit, task" Critical category. Blast radius: any Shipit instance hosting multiple onboarded organizations/repositories is affected; any onboarded (even minimally privileged) attacker can target any other repository already known to Shipit (repo names are discoverable/guessable), repeatedly, since nothing rate-limits or further validates this per request.

### Likelihood Explanation
Preconditions: the Shipit instance must host more than one organization's `webhook_secret` (documented multi-org config in `lib/shipit.rb`/`docs/setup.md`), and the victim repository must already exist as a `Shipit::Repository` row (onboarded). The attacker only needs to control one onboarded organization's webhook secret — which they legitimately possess if they self-onboarded their own org/app installation. Cost is a single crafted HTTP POST with a correctly computed HMAC-SHA1 signature; no GitHub-side action or session/token is required. This is fully repeatable against any repository name known to the attacker.

### Recommendation
After signature verification succeeds, enforce that the resolved `Repository` (used for stack mutation) belongs to the same `repository_owner` that authenticated the request — e.g., in `Handler#stacks`/`#repository_name`, compare `payload.dig('repository','full_name').split('/').first` against `payload.dig('repository','owner','login')` (or reject/`head(422)` in `WebhooksController` when these mismatch before dispatching to handlers). Alternatively, thread the verified `repository_owner` through to handlers and have `Repository.from_github_repo_name` scoped/asserted against it rather than trusting `full_name` alone.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb` (existing suite covers `verify_signature`):
1. Set up two orgs in test secrets (multi-org github config, as in `test/dummy/config/secrets_double_github_app.yml`): `OrgOne` (attacker) with a known `webhook_secret`, and `OrgTwo` (victim) — create a `Shipit::Repository` with `owner: "orgtwo"`, `name: "victim-repo"` and an associated `Stack`.
2. Build a `status` (or `push`) webhook JSON payload where `repository.owner.login = "orgone"` (attacker) but `repository.full_name = "orgtwo/victim-repo"` (victim), with a valid `sha` matching an existing/creatable commit context.
3. Compute `X-Hub-Signature` as `sha1=` + `OpenSSL::HMAC.hexdigest('sha1', OrgOne_webhook_secret, raw_body)`.
4. POST to `/webhooks` with `X-Github-Event: status` and this signature.
5. Assert: `response` is `:ok` (i.e., `verify_signature` passed using OrgOne's secret) AND a `Shipit::Status` (or `Commit`) row was created scoped to OrgTwo's `Stack`/`Repository` — proving `repository_owner` (`"orgone"`, used for verification) != the owner of the mutated repository (`"orgtwo"`), i.e. the binding `verified_owner == mutated_repo_owner` is false while the request still succeeds.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
