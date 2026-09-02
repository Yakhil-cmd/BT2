### Title
Cross-organization Status forgery: webhook signature is bound to an attacker-declared JSON field, not to the resource actually written - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret used to authenticate an inbound webhook using an **attacker-supplied JSON field** (`repository.owner.login`, or `organization.login` as a fallback), rather than any value bound to the resource that the handler subsequently mutates. [1](#0-0)  `StatusHandler#process` then acts on a completely different, independently attacker-controlled field (`sha`) with **no scoping to any organization or repository at all**, looking the commit up globally across the entire Shipit installation. [2](#0-1)  Because the two fields are never cross-checked, a party that legitimately holds a valid `webhook_secret` for *any* organization configured in the Shipit instance can forge a "status" webhook that writes a fake commit `Status` (e.g. `state: "success"`) for a commit belonging to a completely unrelated organization/stack.

### Finding Description
This is a structural analog of the reported `dt` bug: in the Canto report, a value used to gate/scope a state update (`dt`) was not kept consistent with the value that was actually verified/derived (`tickActiveEnd - tickActiveStart`), letting stale/incorrect bounds leak into `timeWeightedWeeklyPositionInRangeConcLiquidity_`. Here, the value used to *authenticate* the webhook (`repository_owner`, derived from `params.dig('repository','owner','login') || params.dig('organization','login')`) is never re-checked against the value the handler actually **acts on**:

```ruby
# app/controllers/shipit/webhooks_controller.rb
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`verify_webhook_signature` only proves that *some* configured organization's HMAC key was used to sign the raw body — it does not prove anything about the *content* of the payload beyond that raw byte string, and Shipit supports multiple independent GitHub Apps/secrets keyed per organization (confirmed by `secrets_double_github_app.yml` and `Shipit.github(organization:)`). [3](#0-2) 

The `status` handler then completely ignores `repository`/`organization` and looks up the target purely by `sha`, globally:

```ruby
# app/models/shipit/webhooks/handlers/status_handler.rb
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

`Handler#stacks`/`repository_name` (which scope to `payload.dig('repository','full_name')`) are never invoked by `StatusHandler`. [5](#0-4)  This is the exact class of bug flagged in the report: the value that gates/authorizes an action (organization used for signature verification) is decoupled from the value that determines what state actually gets mutated (`sha`, matched with no owner/org scoping), so the "equality" the system implicitly relies on — *authenticated organization == repository being written* — is never enforced.

### Impact Explanation
A party holding a legitimately-issued `webhook_secret` for Organization A (i.e. they only administer their own GitHub App installation/org onboarded to this shared Shipit instance) can forge an HTTP POST to `/webhooks` with:
- `X-Github-Event: status`
- Body containing an arbitrary `sha` (of any commit already tracked by Shipit, e.g. a public commit sha of Organization B's repository) and `state: "success"`, `context: <required CI context>`
- Signature computed with Organization A's own secret

Because `verify_signature` only validates that the byte-stream was signed by *some* configured org's key, and `StatusHandler` performs no per-repository/per-organization scoping, this forged status is written to Organization B's `Commit` record. Since Shipit's merge queue (`MergeRequest#all_status_checks_passed?` via `StatusChecker`) and deploy safety checks (`ci.require`) gate merges/deploys on `Status` records, this can be used to fabricate a passing CI status for a victim stack/commit and enable an **unauthorized merge or deploy** for a repository the attacker does not control — a cross-tenant "cross-repository write" that meets the Critical/High impact bar (unauthorized deploy/merge across repository boundaries via a decoupled trust binding).

### Likelihood Explanation
Exploitability requires only:
1. The Shipit instance is multi-tenant (multiple orgs/`webhook_secret`s configured — an explicitly supported and documented configuration, cf. `docs/setup.md` and `secrets_double_github_app.yml`).
2. The attacker administers a legitimate, low-privilege GitHub App/webhook installation for their own organization (no Shipit session, `ApiClient` token, or stolen secret needed — they use their own valid credentials for their own org).
3. The attacker knows the target commit `sha` (public for public repos, or otherwise obtainable through normal Shipit/GitHub visibility of the target stack).

No privileged Shipit account, API token, or credential theft is required, satisfying the "unprivileged attacker" and "no host-mounting caveat" constraints — the primitive is exposed by design once >1 organization/app is configured, which is a first-class supported deployment topology of this engine.

### Recommendation
Bind the value used by every handler to the value that was actually authenticated:
- Add a check in `Handler` (or a shared `before` filter) verifying that `payload.dig('repository','owner','login')` (or `organization.login`) equals the `repository_owner` value used in `verify_signature`, and reject otherwise.
- Scope `StatusHandler#process` (and any other handler that doesn't already use `stacks`/`repository_name`) to the commit's owning stack/repository derived from the verified organization, instead of a global `Commit.where(sha:)` lookup.

### Proof of Concept
1. Configure Shipit with two GitHub Apps/organizations, `org-a` (attacker-controlled) and `org-b` (victim), each with its own `webhook_secret` (a normal, documented multi-org deployment).
2. Attacker computes `sha1=HMAC(org_a_webhook_secret, body)` for a JSON body:
```json
{
  "sha": "<known sha of org-b commit>",
  "state": "success",
  "context": "required-ci-check",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-a/some-repo" }
}
```
3. POST this body with `X-Github-Event: status` and the computed `X-Hub-Signature` to `/webhooks`.
4. `verify_signature` resolves `Shipit.github(organization: "org-a")` and validates successfully against the attacker's own legitimate secret. [6](#0-5) 
5. `StatusHandler#process` matches `Commit.where(sha: params.sha)` — the victim org-b commit — and calls `create_status_from_github!`, injecting a forged "success" status onto org-b's commit despite the signature having been verified only against org-a's key. [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** test/unit/shipit_test.rb (L11-22)
```ruby
    test ".github uses indifferent access to search through the Github applications" do
      secrets = ActiveSupport::OrderedOptions.new
      secrets.merge!(YAML.load_file('test/dummy/config/secrets_double_github_app.yml'))
      secrets.deep_symbolize_keys!
      Shipit.stubs(:secrets).returns(secrets)
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'OrgOne'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgOne))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'orgone'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :orgone))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgTwo))
      Shipit.unstub(:secrets)
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
