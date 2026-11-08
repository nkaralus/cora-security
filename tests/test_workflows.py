"""The compile workflow's own step scripts, run for real under the shell GitHub uses, in a scratch clone with a stubbed
`gh` and a local bare repo to push to. Issue #5 went green, said "committed to main" and closed, with nothing
committed: `accept | tee` hid the refusal (no pipefail), and the close step never asked whether a commit happened."""
import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WF = yaml.safe_load((ROOT / ".github/workflows/compile.yml").read_text())
STEPS = {s.get("name"): s for s in WF["jobs"]["compile"]["steps"]}

pytestmark = pytest.mark.skipif(not (shutil.which("bash") and shutil.which("git")), reason="needs bash and git")

BODY = textwrap.dedent('''\
    proof

    ```json
    {"schema":"cora.security.violation/v1","report_id":"d0c1e2f3a4b5c6d7e8f9a0b1c2d3e4f5","observed_hour":"2026-11-07T21:00:00Z","task_ref":"9c1e5a7b3d2f","process":null,"violation":{"type":"tracker_domain","list":"trackers-starter","entry":"doubleclick.net","destination":{"ip":null,"port":443,"ip_class":"public"},"proto":"tcp","via":"syn_tap"},"response":{"verdict":"ISOLATE","enforced":true,"policy":null,"model_confidence":0.9}}
    ```
    ''')


def sha(text):
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.fixture
def repo(tmp_path):
    """A clone of this repo's tools/schema/policy/blocklists with one commit, pushing to a bare origin."""
    work, origin = tmp_path / "work", tmp_path / "origin.git"
    work.mkdir()
    for d in ("tools", "schema", "policy", "blocklists", "submissions"):
        shutil.copytree(ROOT / d, work / d, ignore=shutil.ignore_patterns("__pycache__"))
    g = lambda *a: subprocess.run(["git", *a], cwd=work, check=True, capture_output=True)  # noqa: E731
    g("init", "-q", "-b", "main")
    g("config", "user.email", "t@t"), g("config", "user.name", "t")
    g("add", "-A"), g("commit", "-qm", "base")
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    g("remote", "add", "origin", str(origin)), g("push", "-q", "-u", "origin", "main")   # as actions/checkout leaves it
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "gh").write_text('#!/bin/sh\necho "gh $*" >> "$GH_LOG"\ncase "$1" in api) printf "%s\\n" "$MARKER" ;; esac\n')
    (bin_ / "gh").chmod(0o755)
    return work, bin_, tmp_path


def step(name, work, bin_, tmp, event="issues", body=BODY, marker=None):
    """Run one workflow step's script the way GitHub does: bash -eo pipefail (the workflow's defaults.run.shell)."""
    out = tmp / "gh_output"
    out.touch()
    env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}", GH_LOG=str(tmp / "gh.log"), GITHUB_OUTPUT=str(out),
               ISSUE_BODY=body, MARKER=marker if marker is not None else sha(body), NUM="5", GH_REPO="o/r",
               EVENT=event, GITHUB_SERVER_URL="https://x", GITHUB_RUN_ID="1", SHA="")
    assert WF["defaults"]["run"]["shell"] == "bash"
    r = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", STEPS[name]["run"]], cwd=work,
                       env=env, capture_output=True, text=True)
    outputs = dict(l.split("=", 1) for l in out.read_text().split())
    return r, outputs


# ---------------------------------------------------------------- the shell

def test_every_run_step_gets_pipefail():
    assert WF["defaults"]["run"]["shell"] == "bash"               # GitHub: bash --noprofile --norc -eo pipefail
    ingest = yaml.safe_load((ROOT / ".github/workflows/ingest.yml").read_text())
    assert ingest["defaults"]["run"]["shell"] == "bash"


def test_nothing_pipes_accept_into_tee():
    assert "| tee" not in STEPS["Accept submission"]["run"]


# ---------------------------------------------------------------- accept

def test_a_refused_accept_fails_the_step_and_keeps_its_reason(repo):
    work, bin_, tmp = repo
    r, _ = step("Accept submission", work, bin_, tmp, marker="f" * 64)      # body changed after validation
    assert r.returncode != 0
    assert "changed after the last validation" in (work / "refusal.txt").read_text()
    assert not list((work / "submissions/accepted").glob("d0c1*.json"))


def test_an_accepted_report_writes_its_file(repo):
    work, bin_, tmp = repo
    r, _ = step("Accept submission", work, bin_, tmp)
    assert r.returncode == 0, r.stderr
    assert (work / "accepted_id").read_text().strip() == "d0c1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"
    assert (work / "submissions/accepted/d0c1e2f3a4b5c6d7e8f9a0b1c2d3e4f5.json").is_file()


# ---------------------------------------------------------------- commit, and the right to say so

def test_accept_compile_commit_push_end_to_end(repo):
    work, bin_, tmp = repo
    assert step("Accept submission", work, bin_, tmp)[0].returncode == 0
    assert step("Compile blocklists", work, bin_, tmp)[0].returncode == 0
    r, out = step("Commit", work, bin_, tmp)
    assert r.returncode == 0, r.stderr
    assert out["committed"] == "true" and out["sha"]
    log = subprocess.run(["git", "--git-dir", str(tmp / "origin.git"), "log", "--format=%an %s", "-1", "main"],
                         capture_output=True, text=True).stdout
    assert log.startswith("github-actions[bot] blocklists: accept report d0c1e2f3") and "(closes #5)" in log
    assert "doubleclick.net" in (work / "blocklists/community-trackers.txt").read_text()


def test_an_issue_run_with_nothing_staged_fails_instead_of_claiming_a_commit(repo):
    """Issue #5: accept had refused, so nothing was staged; the old step said 'nothing changed' and exited 0."""
    work, bin_, tmp = repo
    r, out = step("Commit", work, bin_, tmp, event="issues")
    assert r.returncode != 0 and "nothing was staged" in r.stdout + r.stderr
    assert out.get("committed") != "true"


def test_a_manual_recompile_with_nothing_new_is_fine(repo):
    work, bin_, tmp = repo
    r, out = step("Commit", work, bin_, tmp, event="workflow_dispatch")
    assert r.returncode == 0 and out["committed"] == "false"


def test_the_close_step_only_runs_after_a_real_commit():
    cond = STEPS["Close issue"]["if"]
    assert "steps.commit.outputs.committed == 'true'" in cond and "success()" in cond
    assert STEPS["Commit"]["id"] == "commit"


def test_a_refusal_reaches_the_issue(repo):
    work, bin_, tmp = repo
    (work / "refusal.txt").write_text("refused: issue body changed after the last validation; re-review it\n")
    r, _ = step("Report failure", work, bin_, tmp)
    assert r.returncode == 0, r.stderr
    log = (tmp / "gh.log").read_text()
    assert "remove-label accepted" in log and "refused, nothing was committed" in log
    assert "changed after the last validation" in log


def test_the_test_workflow_runs_when_a_workflow_changes_and_installs_what_the_tests_import():
    t = yaml.safe_load((ROOT / ".github/workflows/test.yml").read_text())
    on = t.get("on", t.get(True))                                  # PyYAML reads a bare `on:` key as True
    assert ".github/workflows/**" in on["push"]["paths"]
    reqs = (ROOT / "tools/requirements-dev.txt").read_text().lower()
    assert "pyyaml==" in reqs                                      # pinned, like every other dependency here
