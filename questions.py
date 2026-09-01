import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 20
# todo: the GitLab namespace/project path, for example group/project
SOURCE_REPO = 'Shopify/shipit-engine'
# todo: the name of the repository
REPO_NAME = 'shipit-engine'

run_number = os.environ.get('GITHUB_RUN_NUMBER', '0')


def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index"""
    return (int(run_number) - 1) % max_index + 1


def load_repository_urls():
    """Load repository URLs from repositories.json."""
    repo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repositories.json")
    if not os.path.exists(repo_file):
        return []

    try:
        with open(repo_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    return [url for url in data if isinstance(url, str) and url.strip()]


if run_number == "0":
    BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
    repository_urls = load_repository_urls()
    if repository_urls:
        run_index = get_cyclic_index(run_number, len(repository_urls))
        BASE_URL = repository_urls[run_index - 1]
    else:
        BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"

scope_files = [
    # =================================================================================
    # LENS: FROM A GITHUB PAYLOAD TO A SHELL ON THE DEPLOY HOST.
    # Shipit is a deployment engine: it turns bytes it receives - a webhook body, a pull
    # request branch, a label, a session cookie, a basic-auth token - into three things:
    # a record it writes on some tenant's behalf, a deploy it triggers, and a command it
    # runs with `GITHUB_TOKEN` in the process environment. Every file below sits on the
    # path between attacker-reachable input and one of those three outcomes. A question
    # belongs here only if it closes on a binding that must hold across that path.
    # =================================================================================

    # -- The unauthenticated front door: webhook receipt and signature ----------------
    # `WebhooksController` picks the verifying GitHub App from the UNSIGNED body
    # (`repository.owner.login`), `GitHubApp#verify_webhook_signature` returns true when
    # that org has no `webhook_secret`, and the handlers then act on `repository.full_name`
    # from the same body.
    "app/controllers/shipit/webhooks_controller.rb",
    "lib/shipit/github_app.rb",
    "lib/shipit.rb",
    "config/routes.rb",
    "lib/shipit/engine.rb",

    # -- What a webhook body is allowed to mutate -------------------------------------
    # Handler dispatch, cross-repository writes (`StatusHandler` matches on bare SHA),
    # team membership grants, and the review-stack lifecycle that provisions a stack from
    # an arbitrary contributor's pull request branch.
    "app/models/shipit/webhooks.rb",
    "app/models/shipit/webhooks/handlers/handler.rb",
    "app/models/shipit/webhooks/handlers/status_handler.rb",
    "app/models/shipit/webhooks/handlers/push_handler.rb",
    "app/models/shipit/webhooks/handlers/check_suite_handler.rb",
    "app/models/shipit/webhooks/handlers/membership_handler.rb",
    "app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb",
    "app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb",
    "app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb",
    "app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb",
    "app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb",
    "app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb",
    "app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb",
    "app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb",
    "app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb",

    # -- Who the request is, and what it is allowed to do -----------------------------
    "app/controllers/concerns/shipit/authentication.rb",
    "app/controllers/shipit/shipit_controller.rb",
    "app/controllers/shipit/github_authentication_controller.rb",
    "app/controllers/shipit/api/base_controller.rb",
    "app/controllers/shipit/api/ccmenu_controller.rb",
    "app/controllers/shipit/merge_status_controller.rb",
    "app/controllers/shipit/ccmenu_url_controller.rb",
    "app/controllers/shipit/status_controller.rb",
    "app/models/shipit/api_client.rb",
    "app/models/shipit/unlimited_api_client.rb",
    "app/models/shipit/user.rb",
    "app/models/shipit/anonymous_user.rb",
    "app/models/shipit/command_line_user.rb",
    "app/models/shipit/team.rb",
    "app/models/shipit/membership.rb",
    "lib/shipit/simple_message_verifier.rb",
    "lib/shipit/same_site_cookie_middleware.rb",

    # -- Everything that ends in a process being spawned ------------------------------
    # `Command#start` spawns `interpolated_arguments`; `unbundled_env` is the merge of
    # `Shipit.env`, the stack env, the deploy spec's `machine_env`, the review stack's
    # PR labels and the task's own env, and it carries `GITHUB_TOKEN` and `GIT_ASKPASS`.
    "lib/shipit/command.rb",
    "lib/shipit/commands.rb",
    "lib/shipit/stack_commands.rb",
    "lib/shipit/task_commands.rb",
    "lib/shipit/deploy_commands.rb",
    "lib/shipit/rollback_commands.rb",
    "lib/shipit/review_stack_commands.rb",
    "lib/shipit/environment_variables.rb",
    "lib/shipit/flock.rb",
    "app/models/shipit/deploy_spec.rb",
    "app/models/shipit/deploy_spec/file_system.rb",
    "app/models/shipit/task_definition.rb",
    "app/models/shipit/variable_definition.rb",

    # -- The records that decide what gets deployed, where, and as whom ---------------
    "app/models/shipit/stack.rb",
    "app/models/shipit/review_stack.rb",
    "app/models/shipit/repository.rb",
    "app/models/shipit/task.rb",
    "app/models/shipit/deploy.rb",
    "app/models/shipit/rollback.rb",
    "app/models/shipit/commit.rb",
    "app/models/shipit/merge_request.rb",
    "app/models/shipit/pull_request.rb",
    "app/models/shipit/review_stack_provisioning_queue.rb",
    "app/models/shipit/hook.rb",
    "app/models/shipit/delivery.rb",
    "app/validators/ascii_only_validator.rb",
    "app/validators/subset_validator.rb",

    # -- Authenticated write surfaces and the jobs they enqueue -----------------------
    "app/controllers/shipit/stacks_controller.rb",
    "app/controllers/shipit/tasks_controller.rb",
    "app/controllers/shipit/deploys_controller.rb",
    "app/controllers/shipit/commits_controller.rb",
    "app/controllers/shipit/api_clients_controller.rb",
    "app/controllers/shipit/api/stacks_controller.rb",
    "app/controllers/shipit/api/tasks_controller.rb",
    "app/controllers/shipit/api/deploys_controller.rb",
    "app/controllers/shipit/api/hooks_controller.rb",
    "app/controllers/shipit/api/outputs_controller.rb",
    "app/controllers/shipit/api/merge_requests_controller.rb",
    "app/jobs/shipit/perform_task_job.rb",
    "app/jobs/shipit/github_sync_job.rb",
    "app/jobs/shipit/cache_deploy_spec_job.rb",
    "app/jobs/shipit/continuous_delivery_job.rb",
    "app/jobs/shipit/deliver_hook_job.rb",

    # =================================================================================
    # NOT IN THIS VARIANT:
    # * test/** (including test/dummy), docs/**, examples/**, contrib/**, script/**,
    #   vendor/**, db/migrate/**, app/assets/**, template.rb, Rakefile, *.gemspec,
    #   Gemfile*, dev.yml, *.md - tests, fixtures, generated and configuration files.
    # * app/helpers/**, app/serializers/** and app/views/** carry no authentication or
    #   execution decision.
    # =================================================================================
]


target_scopes = [
    "Critical. THE BODY CHOOSES ITS OWN VERIFIER. `WebhooksController#verify_signature` reads `repository_owner` - `params.dig('repository','owner','login') || params.dig('organization','login')` - out of the UNSIGNED request body, hands it to `Shipit.github(organization:)`, and verifies the HMAC with that app's `webhook_secret`; `GitHubApp#verify_webhook_signature` returns `true` outright when that org's config has no `webhook_secret`, and only accepts `sha1`. `#create` then re-parses `request.raw_post` and every handler resolves its target from `repository.full_name` in the same body. Show a single POST /webhooks whose body names one organization for verification and another organization's repository for the handler, or names an org with no configured secret, and land it on a real stack. Binding: the organization whose `webhook_secret` verified the bytes == the organization owning the repository, stack, commit or team the handler writes.",

    "Critical. A STATUS WEBHOOK IS NOT SCOPED TO A REPOSITORY AT ALL. `StatusHandler#process` is `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` - it never consults `Handler#stacks`, `repository.full_name`, or the commit's own stack, so a `state: success` status for any SHA rewrites that commit's CI state in EVERY stack of EVERY repository Shipit knows. `Commit#deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))`, which `Stack#trigger_continuous_delivery` and `MergeRequest#all_status_checks_passed?` consult. Show a status event the attacker can legitimately cause on a repository they control (same SHA, e.g. an empty-tree or copied commit) marking another tenant's commit green, and follow it through to a continuous deployment or a queued merge. Binding: the repository a `Status` is written against == the repository named in the payload that carried it.",

    "Critical. AN OUTSIDE CONTRIBUTOR'S BRANCH BECOMES THE COMMAND LINE. `PullRequest::OpenedHandler#provision?` is `repository.review_stacks_enabled && repository.provisioning_behavior_allow_all? || (allow_with_label? && label) || (prevent_with_label? && !label)` - Ruby's `&&`/`||` precedence means the last two branches never test `review_stacks_enabled`. `ReviewStackAdapter#create!` then builds a `ReviewStack` with `branch: params.pull_request.head.ref` and `environment: \"pr#{params.number}\"`, queues it for provisioning, and `TaskCommands#perform` executes `@task.definition.steps` read by `DeploySpec::FileSystem` from `shipit.yml` in that branch's checkout via `Command#start` -> `PTY.spawn`. Show an unprivileged pull request causing a stack to be created and its attacker-authored steps to run, on a repository whose review stacks were never enabled. Binding: the ref whose `shipit.yml` supplies the executed steps == a ref an authorized Shipit user approved for that stack.",

    "Critical. PULL REQUEST LABELS ARE WRITTEN STRAIGHT INTO THE PROCESS ENVIRONMENT. `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |name, h| h[name.upcase] = 'true' }` into the stack env with no name whitelist; `TaskCommands#env` merges that with `Shipit.env`, `deploy_spec.machine_env` and `@task.env`, and `Command#unbundled_env` merges the result over `BASE_ENV` and the `PATH` Shipit builds, then passes it as the env hash to `PTY.spawn`. `PullRequest::LabelCapturingHandler#capture_labels` is what persists those names from the webhook body. Show a label name that becomes an interpreter- or loader-honoured variable (`PATH`, `GIT_ASKPASS`, `BUNDLE_PATH`, `RUBYOPT`, `LD_PRELOAD`, `GIT_SSH_COMMAND`) in the deploy process, and state what it executes. Binding: the set of keys in `Command#unbundled_env` == the set of variables the deploy spec's `machine_env` and `VariableDefinition` list permit.",

    "Critical. A STEP IS A STRING, AND THE ENVIRONMENT FILTER ONLY CHECKS NAMES. `Command#parse_arguments` keeps each configured step as one string and `PTY.spawn(env, *interpolated_arguments)` runs a single-element argv through a shell; `EnvironmentVariables#interpolate` substitutes `$WORD` with `Shellwords.escape(@env.fetch(...) { ENV[...] })`, falling back to Shipit's own process ENV when the key is absent; `EnvironmentVariables#permit` compares only `variable_definitions.map(&:name)` and never inspects values; `TaskDefinition#render_title` does `@title % env.symbolize_keys`. Show a task or deploy env value, an unset variable name, or a `machine_env` entry that changes what the shell executes or leaks a Shipit process secret into the task output. Binding: the bytes handed to the shell == the step string as written in the repository's `shipit.yml`, with every interpolated value escaped exactly once.",

    "Critical. A WEBHOOK GRANTS ACCESS TO SHIPIT ITSELF. `MembershipHandler#process` calls `Team.find_or_create_by!(github_id: params.team.id)` and `User.find_or_create_by_login!(params.member.login)` then `team.add_member(member)` on `action == 'added'`, taking the team id, slug, organization and member login entirely from the payload. `Authentication#force_github_authentication` renders a 403 unless `current_user.authorized?`, and `User#authorized?` is `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` - membership rows are the whole authorization model. Show a membership event, reaching `create` through the verification gap of scope 1 or through an organization the attacker can genuinely emit events for, that inserts the attacker's login into a team id listed in `Shipit.github_teams`. Binding: a `Membership` row for a team in `Shipit.github_teams` == a membership GitHub actually reports for that team.",

    "Critical. THE SESSION IS BOUND AFTER THE FACT, NOT AT THE START. `GithubAuthenticationController#callback` is `ActionController::Base` with no `protect_from_forgery`, is routed for both GET and POST, sets `session[:user_id] = sign_in_github(auth)` and `session[:authenticated] = true` WITHOUT `reset_session`, and redirects to `request.env['omniauth.origin']` unfiltered. `Authentication#find_current_user` is `session[:user_id].present? && User.find_by(id: session[:user_id])`, and `User.find_or_create_from_github` keys on `github_user.id` while `find_or_create_by_login!` keys on a login string. Show a fixed or attacker-planted session surviving a victim's login, a callback completed cross-site, or an identity that resolves to a `User` row other than the GitHub account that authenticated - then use it against a stack the victim can deploy. Binding: the `User` row `session[:user_id]` names == the GitHub account that completed this OAuth exchange in this session.",

    "Critical. AN API TOKEN'S STACK SCOPE IS NOT ENFORCED EVERYWHERE IT MATTERS. `Api::BaseController#authenticate_api_client` joins basic-auth parts with `token = parts.select(&:present?).join('--')` before `ApiClient.authenticate`, which is a bare `SimpleMessageVerifier` over `Shipit.api_clients_secret` (falling back to `secret_key_base`) whose payload is a decimal id; `#stacks` narrows to `current_api_client.stack_id` but `Api::CCMenuController` overrides both `stack` (`Stack.from_param!`) and `authenticate_api_client` to accept `ApiClient.authenticate(params[:token])` from the query string, and `CCMenuUrlController#fetch` mints and hands out exactly such a URL. `#identify_user` trusts the `X-Shipit-User` header for attribution while `require_permission!` only ever checks the client. Show a token or a token-bearing URL that reads or acts on a stack outside its own scope, or an id/permission comparison that accepts a value it should not. Binding: the stack an API request touches ∈ the stacks `current_api_client.stack_id` authorises, and the permission checked == the permission the action needs.",

    "High. ROUTES THAT NEVER ASK WHO IS CALLING. `MergeStatusController` declares `skip_authentication only: %i[check show]`, sets `X-Frame-Options: ALLOWALL`, and derives its stack from `params[:referrer]` through `ReferrerParser`; `StatusController#version` is a bare `ActionController::Base`; `Pubsubstub::StreamAction` is mounted at `/events` inside the engine's own routes with no authentication concern in front of it; `SameSiteCookieMiddleware` rewrites every cookie to `SameSite=None` when enabled. Deploy and task output (`Task#chunk_output`, the `tail` and `.txt` renderings) is where `GITHUB_TOKEN`-bearing commands print. Show an unauthenticated or cross-origin request that reads stack state, a live task stream or deploy output, or that rides a victim's cookie into a state-changing merge-queue action. Binding: every response carrying stack, task or output data was produced after `force_github_authentication` and `authorized?` both passed for the caller.",

    "Critical. THE MISSING BINDING - what nobody built. There is no notion of an untrusted contributor anywhere in this engine: no code path records WHICH organization's webhook secret authenticated a payload and re-checks it before writing, nothing marks a `ReviewStack` branch as fork-authored before its `shipit.yml` steps are executed, and no allowlist ever constrains the KEYS of the environment hash that reaches `PTY.spawn`. Identify the FIRST point at which GitHub-sourced or attacker-sourced bytes - a webhook field, a PR head ref, a label name, a commit message parsed by `User.find_or_create_author_from_github_commit`, a `Stack#base_path` segment - become a shell argument, an environment key, a deploy trigger or an authorization row without any authenticated actor in between. Prove it with one minitest integration test asserting both the value written and the value that authenticated it, and show that once they diverge nothing in the engine ever reconciles them.",
]


scope_scan = [
]


def question_generator(target_file: str) -> str:
    """
    Generate deployment-trust audit questions for one shipit-engine target.

    ```
    target_file format:
    "'File Name: app/models/shipit/webhooks/handlers/status_handler.rb -> Scope: Critical. ...'"
    """

    prompt = f"""
    ```

    Generate authorization and code-execution security audit questions for this exact
    shipit-engine target:

    {target_file}

    Project focus:
    Shipit is a Rails engine that deploys code. Untrusted bytes enter through four doors:
    a GitHub webhook (`WebhooksController` -> `Webhooks::Handlers::*`, where the UNSIGNED
    body picks the app whose `webhook_secret` verifies it), a pull request an outside
    contributor opens (branch name, labels, title, and the `shipit.yml` on that branch),
    the browser session (`Authentication`, the OmniAuth callback), and the API
    (`Api::BaseController`, basic-auth or a `token` query param). Those bytes end up in
    three places: a database row written on some tenant's behalf, a deploy or merge that
    ships code, and a `Command`/`PTY.spawn` whose environment carries `GITHUB_TOKEN` and
    `GIT_ASKPASS`. Anything that crosses from one repository to another, or from a payload
    to a process, without an authenticated actor in between is the bug.

    Rules:
    * Treat `File Name:` as the exact file.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Use exact Ruby symbols (module, class, method, constant, ivar) as they appear in the file.
    * EVERY question must close on a binding that must hold across a call. State it explicitly.
      Narrative questions with no stated binding are rejected.
    * Attacker is unprivileged only: any GitHub user who can open a pull request, push to a
      fork, name a branch, add a label to their own PR, write a commit message, and emit
      webhooks from a repository they own; and any internet user who can send HTTP requests
      to the Shipit host, including POST /webhooks.
    * Attacker is NOT a Shipit operator, not a member of any team in `Shipit.github_teams`,
      not a repository maintainer, and never holds a Shipit session, an `ApiClient` token,
      `api_clients_secret`, `secret_key_base`, a GitHub App private key, or a
      `webhook_secret`. No TLS interception, no local or physical access, no compromised
      dependency, no social engineering.
    * Assume the host application mounts this engine as documented in README.md. The bug
      must be in this engine's code, not in a hypothetical host app misusing it.
    * PROGRAM EXCLUSIONS - a question landing in any of these wastes the whole batch:
      - test/** (including test/dummy), docs/**, examples/**, contrib/**, script/**,
        vendor/**, db/migrate/**, app/assets/**, template.rb, Rakefile, *.gemspec,
        Gemfile*, dev.yml and *.md are OUT OF SCOPE.
      - Denial of service, rate limiting, retry/backoff, job queue depth, resource
        exhaustion, unbounded collections and memory hygiene are OUT OF SCOPE.
      - Defects in third-party gems (octokit, faraday, omniauth, pubsubstub, state_machines,
        explicit-parameters) with no exploit path through this engine's own code are OUT OF
        SCOPE.
      - Also excluded: leaked keys or credentials, privileged Shipit or GitHub accounts,
        best-practice notes, feature requests, missing security headers on their own,
        self-XSS, and theoretical findings with no demonstration.
      - A weakness in this engine that manipulates a third-party gem into unsafe behaviour
        remains fully in scope.
    * IN-SCOPE IMPACTS - every question must land on one and name it:
      Critical: remote code execution on the deploy host (an attacker-influenced string or
      environment key reaching `Command#start` / `PTY.spawn`); authentication bypass (a
      forged webhook, session or API token accepted); exfiltration of `GITHUB_TOKEN`, a
      user's `github_access_token`, `api_clients_secret` or deploy-time secrets; a payload
      for one repository mutating another repository's stack, commit, task or team;
      unauthorized deploy, rollback or merge of attacker-controlled code.
      High: escalation into `Shipit.github_teams` authorization; unauthenticated read of
      stack state, task streams or deploy output; SSRF carrying the app's GitHub
      credentials; session fixation or forced OAuth completion.
    * Every question must be a concrete real-world scenario an unprivileged attacker can
      execute against a running Shipit instance - a pull request they open, a webhook they
      POST, a link they get an operator to visit, an HTTP request they send. No speculative
      resource-hygiene, memory or unbounded-growth questions.
    * A raised exception is a finding only when it lets an unauthenticated request through
      or leaks a secret in its message or in task output - say which.
    * Generate 30 to 40 high-signal questions.
    * At least 70% must land on a Critical impact - RCE, authentication bypass, credential
      exfiltration, cross-repository writes or an unauthorized ship - rather than a High one.
    * Every question must be testable by a minitest test under `test/` (ActiveSupport,
      ActionDispatch::IntegrationTest, WebMock or Mocha) with no live GitHub and no network.
    * Avoid generic checklist questions and repeated root causes.
    * Prefer questions that name TWO values that must be equal and ask whether they are: the
      org that authenticated a payload and the org whose record is written, a ref approved
      and a ref executed, an env key permitted and an env key spawned, a stack a token
      authorises and a stack it touches, a GitHub identity and a `session[:user_id]`.

    Known dead ends - do NOT generate questions about these:
    * Anything needing a Shipit session, an `ApiClient` token, `webhook_secret`,
      `api_clients_secret`, a GitHub App private key, or repository write access.
    * A CVE in a dependency with no reachable path through this engine.
    * The host application choosing not to mount or protect the engine as documented.
    * Findings only reproducible in test/dummy, fixtures or generated files.
    * Timing, DoS, log volume, or an attacker affecting only their own repository with no
      tenant boundary crossed, no command executed and no credential exposed.

    Core bindings (each question must close on one):
    * WEBHOOK PROVENANCE: the organization whose `webhook_secret` verified the body == the
      organization owning the repository, stack, commit or team the handler mutates.
    * REPOSITORY SCOPE: a row written from a payload belongs to the repository named in that
      same verified payload.
    * EXECUTION TRUST: every string reaching `Command#start` and every key in
      `Command#unbundled_env` originates from a ref and a spec an authorized user approved.
    * IDENTITY BINDING: `session[:user_id]`, `current_user` and the acting `ApiClient` ==
      the GitHub identity and scope that authenticated this request.
    * AUTHORIZATION TRUTH: `force_github_authentication`, `authorized?`, `require_permission!`,
      the `stacks` scope and `deployable?` never answer permissively for a caller that lacks
      the right.

    Each question must include:
    1. target class/method;
    2. attacker action (a concrete pull request, webhook POST, or HTTP request with body,
       headers, params or cookies);
    3. preconditions (Shipit configuration, repository settings, existing stack state);
    4. call sequence through the engine;
    5. the binding that breaks, written as an equality;
    6. scoped impact and whose repository, credential or host is affected;
    7. proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Method: class_or_method] Can an unprivileged ATTACKER_ACTION under PRECONDITIONS trigger CALL_SEQUENCE, breaking the binding BINDING_EQUALITY, causing scoped impact: SCOPE_IMPACT against PARTY? Proof idea: minitest test PARAMETERS asserting WEBHOOK_PROVENANCE, REPOSITORY_SCOPE, EXECUTION_TRUST, IDENTITY_BINDING, or AUTHORIZATION_TRUTH.",
    ]
    """
    return prompt


def audit_format(security_question: str) -> str:
    """
    Generate a deployment-trust shipit-engine exploit-validation prompt.
    """

    prompt = f"""# SECURITY AUDIT PROMPT

## Question
{security_question}

## Rules
- Use existing repo context only. Analyze only this question and scoped impact.
- Attacker is unprivileged only: any GitHub user who can open a pull request, push to a fork, name a branch, label their own PR, write a commit message and emit webhooks from a repository they own; and any internet user who can send HTTP requests to the Shipit host, including POST /webhooks. They hold no Shipit session, no `ApiClient` token, no `api_clients_secret`, `secret_key_base`, GitHub App private key or `webhook_secret`, are not in `Shipit.github_teams`, and are not a repository maintainer or Shipit operator.
- Reject TLS interception, local or physical access, compromised dependencies, social engineering, and any path requiring Shipit or GitHub secrets or privileged roles.
- Assume the host app mounts this engine as documented. The bug must be in this engine's code.
- OUT OF SCOPE, reject on sight: `test/**`, `docs/**`, `examples/**`, `contrib/**`, `script/**`, `vendor/**`, `db/migrate/**`, `app/assets/**`, `template.rb`, `Rakefile`, `*.gemspec`, `Gemfile*`, `*.md`; denial of service, rate limiting, retry behaviour, resource exhaustion and memory hygiene; third-party gem defects with no exploit path through this engine's own code; best-practice notes; feature requests; theoretical findings with no demonstration.
- The impact must be one of: Critical - RCE on the deploy host via `Command`/`PTY.spawn`, authentication bypass (forged webhook, session or API token accepted), exfiltration of `GITHUB_TOKEN`, a user's `github_access_token`, `api_clients_secret` or deploy-time secrets, a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge; High - escalation into `Shipit.github_teams` authorization, unauthenticated read of stack state, task streams or deploy output, SSRF carrying the app's GitHub credentials, or session fixation / forced OAuth completion.
- Focus on real impact: a command running that should not, a record written for a repository that did not authenticate it, or a credential leaving the host.

## Validate
- Write the binding the question claims is broken as an explicit equality between two named values BEFORE tracing any code.
- Trace the exact reachable path from the attacker's request or pull request, and record every read and write of `params`/`payload`, `repository_owner`, `repository.full_name`, `session[:user_id]`, `current_user`, `current_api_client.stack_id`, the stack `branch` and `environment`, `Command#args`, and the merged env hash reaching `PTY.spawn`.
- Evaluate both sides of the equality before and after. If they still match, output no vulnerability.
- Check whether `verify_signature`, `GitHubApp#verify_webhook_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema, `force_github_authentication`, `User#authorized?`, `require_permission!`, the `stacks` scope, model validations (`Repository` format, `Stack` environment format, `subset`/`url` validators) or `EnvironmentVariables#permit` already prevent the divergence.
- State what the attacker gains per request and whether it is repeatable against arbitrary repositories or stacks.
- Require exact file/method support and a reproducible minitest proof under `test/` with no live GitHub.

## Output
If valid, output exactly:

### Title
[Bug statement] - ([File: file_path])

### Summary
[2-3 sentences]

### Finding Description
[The broken binding as an equality, the code path, root cause, the attacker's exact request or pull request, exploit flow, and why existing guards fail]

### Impact Explanation
[What is executed, exposed or bypassed, which repository or party, repeatability, blast radius across tenants, matching severity category]

### Likelihood Explanation
[Preconditions, Shipit and repository configuration required, attacker cost, feasibility, repeatability]

### Recommendation
[Specific fix]

### Proof of Concept
[minitest test plan with the exact assertions on both sides of the binding]

If invalid, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict bounty-style validation prompt for shipit-engine claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and Researcher.Md for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- A binding claim is only valid if the report states the broken equality between two named values and shows both sides concretely. Reject prose-only claims.
- Reject anything requiring a Shipit session, an `ApiClient` token, `api_clients_secret`, `secret_key_base`, a GitHub App private key, a `webhook_secret`, membership in `Shipit.github_teams`, repository write access, operator access, TLS interception, local or physical access, a compromised dependency, or social engineering.
- OUT OF SCOPE, reject on sight: `test/**`, `docs/**`, `examples/**`, `contrib/**`, `script/**`, `vendor/**`, `db/migrate/**`, `app/assets/**`, `template.rb`, `Rakefile`, `*.gemspec`, `Gemfile*`, `*.md`; denial of service, rate limiting, retry behaviour, resource exhaustion and memory hygiene; third-party gem defects with no exploit path through this engine's own code; best-practice notes; feature requests; missing security headers alone; self-XSS; theoretical findings with no demonstration.
- The impact must be one of: Critical - RCE on the deploy host, authentication bypass, exfiltration of `GITHUB_TOKEN`, a user's `github_access_token` or `api_clients_secret`, cross-repository writes, or an unauthorized deploy, rollback or merge; High - escalation into `Shipit.github_teams` authorization, unauthenticated read of stack state, task streams or deploy output, SSRF with the app's GitHub credentials, or session fixation / forced OAuth completion.
- Reject claims that depend on the host application not mounting or protecting the engine as documented.
- Reject if the bug was already fixed, publicly disclosed, or is covered by an existing advisory or CHANGELOG entry for a supported version.
- Reject a divergence with no repository, credential, execution or authentication boundary crossed.
- A valid report must be triggerable by an unprivileged attacker against a Shipit instance running the current release.
- A PoC is mandatory. Prefer #NoVulnerability over speculative reports.

## Required Validation Checks
All must pass:
1. Exact in-scope file, class/method, and line references.
2. The binding written explicitly as an equality, with both sides shown before and after.
3. Clear root cause: which unverified payload field, which unscoped query, which unfiltered environment key, which missing authorization check causes the divergence.
4. Reachable exploit path: preconditions -> attacker pull request or HTTP request -> engine call sequence -> observed divergence.
5. `verify_signature`, `GitHubApp#verify_webhook_signature`, the `ExplicitParameters` schemas, `force_github_authentication`, `User#authorized?`, `require_permission!`, the `stacks` scope, model validators and `EnvironmentVariables#permit` reviewed and shown insufficient.
6. Impact stated concretely: which command runs, which credential or which repository's data, and whether it is repeatable against arbitrary tenants.
7. Reproducible proof: minitest test with the asserted values.

## Silent Triage Questions
Before output, internally answer:
- What exactly is the equality, and does it actually fail?
- Can an ordinary GitHub user or internet user trigger it with no secret and no privileged role?
- Is the flaw in this engine's code, not in a dependency or in a careless host app?
- What executes, what credential leaks, or whose repository is written, and is it repeatable?
- Would a Shopify HackerOne triager accept the exploit path?
- What exact test would prove it?

## Output
If valid, output exactly:

Audit Report

## Title
[Clear vulnerability statement] - ([File: file_path])

## Summary
[2-3 sentence summary of the broken binding and impact]

## Finding Description
[Exact code path, the equality, root cause, exploit flow, and why existing guards fail]

## Impact Explanation
[What is executed, exposed or bypassed, affected party, repeatability, severity category]

## Likelihood Explanation
[Attacker capability, preconditions, configuration, cost, feasibility]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or minitest test plan with concrete assertions]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for shipit-engine.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Rules
- Use in-scope engine context only (`app/**` excluding assets, views, helpers and serializers, plus `lib/shipit/**` and `config/routes.rb`). Do not ask for code or claim missing files.
- Use the external report only as a bug-class hint, not as proof.
- Keep only unprivileged-attacker analogs that break a deployment-trust binding: a payload field acted on but never covered by the verified signature, an organization that authenticated versus the repository that is written, a ref approved versus a ref whose `shipit.yml` steps execute, an environment key permitted versus an environment key spawned, a stack a token authorises versus a stack it touches, or a GitHub identity versus the `User` bound to the session.
- OUT OF SCOPE, reject on sight: `test/**`, `docs/**`, `examples/**`, `contrib/**`, `script/**`, `vendor/**`, `db/migrate/**`, `app/assets/**`, `template.rb`, `*.gemspec`, `Gemfile*`, `*.md`; denial of service, rate limiting, retry behaviour, resource exhaustion and memory hygiene; third-party gem defects with no exploit path through this engine's own code; anything requiring a Shipit session, an `ApiClient` token, `webhook_secret`, `api_clients_secret`, a GitHub App private key, repository write access, a privileged account, TLS interception, local access or social engineering; best-practice notes; feature requests; theoretical findings.
- The impact must be one of: Critical - RCE on the deploy host, authentication bypass, exfiltration of `GITHUB_TOKEN`, a user's `github_access_token` or `api_clients_secret`, cross-repository writes, or an unauthorized deploy, rollback or merge; High - escalation into `Shipit.github_teams` authorization, unauthenticated read of stack state, task streams or deploy output, SSRF with the app's GitHub credentials, or session fixation / forced OAuth completion.
- Reject analogs that depend on the host application not mounting the engine as documented, and analogs with no credential, repository, execution or authentication boundary crossed.

## Validate
- Map the bug class to the strongest reachable path in this engine and state the binding it would break as an equality.
- Evaluate both sides before and after the attacker's pull request or request sequence.
- Prove root cause with exact file/method support.
- Accept only concrete RCE, authentication bypass, credential exfiltration, cross-repository writes, an unauthorized ship, or SSRF carrying the app's GitHub credentials.

## Output (Strict)
If valid analog exists, output:

### Title
[Clear vulnerability statement] - ([File: file_path])

### Summary
### Finding Description
### Impact Explanation
### Likelihood Explanation
### Recommendation
### Proof of Concept

If not, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt
