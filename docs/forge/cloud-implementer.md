# Cloud implementer routine — atulg4/constellation

Implementation for this repository is done by a **Claude Code cloud routine** (a scheduled cloud
agent on claude.ai), not by a GitHub Actions job, so no self-hosted runner is required for it.
The routine must obey `AGENTS.md`, `CLAUDE.md` and `agentic-sdlc.toml` exactly as an Actions
implementer would -- including the labeler check the Actions path runs: before claiming an
issue it runs `sdlcctl authorize-labeler`, which reads the issue's label events and requires a
definitive write/maintain/admin permission for whoever applied EACH label of the approval set
(`implementation-approved`, `claude-ready`,
`human-review-required`) most recently -- so a Triage user cannot complete the set after
a writer approved (a 404 is unauthorized; any other failure is unverifiable and the issue is
skipped) -- and requires the issue's title and body to have been last edited BEFORE each of
those labels was last applied, so an edit after approval is never implemented unapproved (an
edit time that cannot be read is unverifiable). The Actions path's other deterministic gates
are commands too, and the routine is gated on their exit codes: `sdlcctl check-request`
parses the issue with the same work-request validator and policy as `prepare-request` and
requires every dependency issue to be closed;
`sdlcctl check-diff` applies the same diff policy as `inspect-diff` (forbidden paths and the
patch caps) to exactly what is about to be pushed -- every path any commit of the series
touches, not only the end state -- under the policy COMMITTED on the default branch (an
uncommitted, loosened `agentic-sdlc.toml` changes nothing), whose head must be the commit
GitHub reports (a re-pointed local `origin/<branch>` is refused), running a git only root
can replace (never a `git` from a writable PATH entry) in an environment of its own;
`sdlcctl renew` -- after implementation, after verification and immediately before pushing --
keeps the lease alive and
fails unless this run still holds it and the issue is still open, so the routine never pushes
over another agent's lease or for a closed issue. The LAST gate, immediately before pushing
and with nothing run between it and the push, is ONE command:
`check-request --expect-digest <digest from step 2> --authorize-labels`. It reads the issue and
its label history once and judges that single snapshot by every rule -- issue open, title and
body unchanged since step 2, a valid request, every dependency closed, and each approval label
last applied by a writer after the last edit -- then reads the issue and its history again and
requires the update time, state, content, labels and events unchanged (a changed title or body
fails at once; any other change is judged afresh, a bounded number of times). So an edit plus
a label re-apply, a reopened dependency or a closed issue at any point before the push stops it:
there is no gap between two separate checks for them to land in.
Keep `lease_ttl_minutes` longer than the longest stage. An issue whose body is not a valid
work request is labelled `claude-blocked` and its lease released; step 1 never
selects a blocked issue.
## Environment setup script

A fresh cloud environment has no `sdlcctl`, and every gate below is an `sdlcctl` command. Paste
this into the setup script of the routine's cloud environment (claude.ai: the environment's
settings); it installs the platform at exactly the commit this repository's workflows pin:

```sh
python3 -m pip install --user --disable-pip-version-check 'agentic-sdlc @ git+https://github.com/atulg4/agentic-sdlc@02ce92be893484415d9f96f4abb75d3724cb7831'
```

`--user` installs `sdlcctl` into `~/.local/bin`, which must be on the routine's PATH. If
`atulg4/agentic-sdlc` is private, the environment needs read access to it. Step 0 of the
prompt checks the install (`sdlcctl --version` must print `commit 02ce92be893484415d9f96f4abb75d3724cb7831`) and
stops the run before anything is claimed when it does not.

**Trust boundary** (Codex 4244027563): the routine's agent runs as the same user that owns this
install -- in Claude Code cloud environments, root -- so it can replace `sdlcctl` (or the git
and gh it calls) after step 0 has checked the version. Installing elsewhere does not change
that: no location is out of reach of an agent running as root, and as root ownership cannot
tell a system file from one the session wrote. The `sdlcctl` gates, like the hooks, are a
guardrail against mistakes and casual misuse, not a sandbox. What enforces the workflow is
server-side: the `Protect main` ruleset (no bypass) and its required review (at
`required_approvals = 0` the human-merge boundary is not enforced; `doctor` says so).

## Routine prompt

Suggested routine prompt (create it with the `schedule` skill or the claude.ai routines UI):

```
Repository: atulg4/constellation. Every run:
0. Run `sdlcctl --version`. It must print `commit 02ce92be893484415d9f96f4abb75d3724cb7831` -- the platform commit
   this document was generated for, installed by the environment's setup script (see
   "Environment setup script" in docs/forge/cloud-implementer.md). If `sdlcctl` is missing or
   names any other commit, STOP: claim nothing, touch no issue, and report that the routine
   environment's setup script is missing or stale (Codex 4242373521).
1. List open issues that carry ALL of: `claude-ready`, `human-review-required`,
   `implementation-approved`
   and do NOT carry `claude-blocked`, and have no open PR referencing them:
   `gh issue list --repo atulg4/constellation --state open --limit 1000
    --search 'label:"claude-ready" label:"human-review-required" label:"implementation-approved" -label:"claude-blocked" sort:created-asc'`.
   This is the candidate list, oldest first; if it is empty, stop. Work through it IN ORDER,
   starting with the oldest: whenever a step below says "take the next issue", move on to the
   next candidate of THIS list (do not list again), and stop only when one issue has been
   claimed and handled or the list is exhausted -- a skipped issue (not authorized,
   unverifiable, or leased by another agent) never ends the run while candidates remain.
1a. Authorize the approval before claiming (labels alone are no authority: Triage users can
   apply them):
   `sdlcctl authorize-labeler --project atulg4/constellation --issue <n>
    --label implementation-approved --label claude-ready
    --label human-review-required`.
   Proceed ONLY on exit 0 (whoever applied EACH of the three labels last has
   write/maintain/admin, and the title and body were last edited BEFORE each label was last
   applied: Codex 4241196649). Exit 3: not authorized -- do not claim; unless you already
   commented so on this issue, comment that a maintainer must review it and re-apply the
   labels, then take the next issue.
   Any other exit: authorization could not be verified -- do not claim, take the next issue.
1b. Claim it before touching code. First name this run's branch ONCE: <branch> is
   `forge/issue-<n>-<stamp>`, where <stamp> is the UTC time now as digits only
   (`date -u +%Y%m%d%H%M%S`). It is new for every run, so a branch an earlier run pushed (say
   its PR could not be opened) never blocks this one (Codex 4241532615); never push to or
   reuse another run's branch. Then claim:
   `sdlcctl claim --project atulg4/constellation --issue <n> --agent cloud-routine
    --session <run id> --branch <branch>`.
   If the claim fails (ANY non-zero exit), first run `sdlcctl release --project atulg4/constellation --issue <n> --session <run id>` with this same <run id>,
   best-effort, whatever it exits (Codex 4243193105: a claim that lost the race may have left
   its marker queued when retracting it failed, and a queued marker becomes authoritative once
   the holder releases; release retracts it, and is harmless for a session that never held
   the issue), then skip that issue and take the next one.
2. Check the request deterministically (the same validator and dependency rule as the Actions
   implement path: Codex 4241434511), with the policy as committed on the default branch
   (Codex 4241614590): `git fetch origin refs/heads/main`, then
   `sdlcctl check-request --project atulg4/constellation --issue <n> --config agentic-sdlc.toml --base origin/main`.
   It prints `content digest: sha256:...`; keep that value as <digest> -- it names the request
   exactly as checked here, and step 4d refuses to publish if the title or body changes after
   this (Codex 4241614582). Exit 0: continue. Exit 3: not a valid work request -- retire it
   so it cannot starve the queue (Codex 4241196636): comment the reason it printed,
   add label `claude-blocked` (step 1 skips it from then on), then `sdlcctl release --project atulg4/constellation --issue <n> --session <run id>`; then go
   back to step 1a with the next candidate of the step 1 list. Exit 4: a dependency issue is
   still open -- `sdlcctl release --project atulg4/constellation --issue <n> --session <run id>` (do NOT block it: it becomes ready once its dependencies close)
   and go back to step 1a with the next candidate. Any other exit: it could not be verified
   -- `sdlcctl release --project atulg4/constellation --issue <n> --session <run id>` and go back to step 1a with the next candidate.
3. `git fetch origin refs/heads/main` and create branch <branch> from
   `origin/main`. Implement the smallest change that satisfies the acceptance
   criteria, tests first, and commit it. Never touch `forbidden_paths` from agentic-sdlc.toml;
   stay within max_changed_files=20 and
   max_diff_lines=2500.
3a. Renew the lease (Codex 4241434506: a lease that expires while you work can be taken over):
   `sdlcctl renew --project atulg4/constellation --issue <n> --session <run id> --config agentic-sdlc.toml`.
   It succeeds ONLY while this run still holds a live lease. On any non-zero exit STOP: do NOT
   push or open a PR -- another agent may own the issue now; run `sdlcctl release --project atulg4/constellation --issue <n> --session <run id>` (it refuses if
   another session holds the lease, which is fine) and end the run. It also fails once the
   issue has been closed (Codex 4241614587): every renewal re-reads the issue's state, and
   once the issue has an open pull request (Codex 4243193102: one opened or linked by someone
   else since the claim) -- that PR already represents the work.
4. Run each, in order; all must pass:
   cargo fetch --locked
   cargo fmt --all --check && cargo clippy --all-targets --locked -- -D warnings
   cargo test --workspace --locked
4a. Renew the lease again, exactly as in step 3a (same command; on failure stop the same way).
4b. Check the diff policy on exactly what will be pushed (Codex 4241434509: the same
   `evaluate_diff` the Actions path applies -- forbidden paths, file, line and byte caps). Commit
   everything first; then `git fetch origin refs/heads/main` and
   `sdlcctl check-diff --project atulg4/constellation --config agentic-sdlc.toml --base origin/main`.
   It diffs the committed HEAD against its merge base with the default branch -- every commit
   of the series, not only the end state (Codex 4241839922) -- under the policy committed on
   the default branch (never your working-tree copy: Codex 4241614590), after proving that
   origin/main is the commit GitHub reports as that branch's head (Codex
   4241839926: a local ref can be re-pointed). On any non-zero exit do NOT push or open a PR:
   comment the reasons it printed on the issue, `sdlcctl release --project atulg4/constellation --issue <n> --session <run id>`, and stop. Make no commit after this
   check.
4c. Verify the lease: run the step 3a renew command once more (it fails if the issue was closed
   meanwhile). On any non-zero exit do NOT push or open a PR; stop as in step 3a.
4d. The final gate, LAST, immediately before pushing -- ONE command that decides everything
   from one snapshot of the issue (Codex 4242264478: two separate checks let an edit plus a
   label re-apply, or a reopened dependency, land between them and pass both):
   `sdlcctl check-request --project atulg4/constellation --issue <n> --config agentic-sdlc.toml --base origin/main --expect-digest <digest> --authorize-labels --label implementation-approved --label claude-ready --label human-review-required`.
   It re-checks the request (Codex 4241614596, 4241614582: a dependency reopened, the issue
   closed, the request edited) and re-authorizes the approval labels as step 1a does (Codex
   4240628982, 4241839918: labels removed and re-applied, or applied by someone without write
   access, while you worked), then reads the issue and its history again and requires them
   unchanged. Proceed to step 5 ONLY on exit 0, and run nothing between this check and the
   push. On any other exit do NOT push or open a PR: `sdlcctl release --project atulg4/constellation --issue <n> --session <run id>` and stop. Exit 5 means the
   title or body changed since step 2: comment (once) that the request changed while it was
   being implemented and a later run will start over from the new text. Exit 7: comment (once)
   that a maintainer must review it and re-apply the labels. Exit 4: a dependency was reopened.
   Exit 6: the issue is no longer open. Exit 8: the issue kept changing while it was checked.
   Exit 9: a pull request for the issue was opened or linked meanwhile (Codex 4243193102) --
   that PR now represents the work; do not open a second one.
5. Push the checked commit at once -- `git push origin HEAD:refs/heads/<branch>`, never
   forced -- and
   open a DRAFT pull request titled "<issue title> (#<n>)" with a summary
   and test plan; link the issue. Then `sdlcctl release --project atulg4/constellation --issue <n> --session <run id>` (the open PR now marks the
   work); on any failure, release it too so another run can retry.
   Never merge, approve, deploy, or edit workflows/policy files.
```

Once the routine is scheduled AND its environment runs the setup script above, record it:
`sdlcctl confirm-cloud-routine` (sets `[automation] cloud_routine_confirmed = true` in
agentic-sdlc.toml). `sdlcctl doctor` cannot see claude.ai routines or their environments and
reports NOT READY until then; `onboard --force` drops the confirmation (it may move the pin), so
re-check the routine and its setup script against this document and confirm again.

Required GitHub state (created by `sdlcctl onboard --apply`): the three labels, the
`Protect main` ruleset requiring the `test` check and review-thread resolution.
CI (`.github/workflows/ci.yml`) provides the `test` check and runs on
`ubuntu-latest`.
