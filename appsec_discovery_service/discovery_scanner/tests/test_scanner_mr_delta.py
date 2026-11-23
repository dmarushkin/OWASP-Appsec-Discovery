"""MR delta restricted to the files the MR changes since its merge-base with the target."""

import os
import subprocess
import uuid
from types import SimpleNamespace

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
                          env={**os.environ, **GIT_ENV}).stdout.strip()


def commit_files(repo, message, files=None, remove=()):
    for name, text in (files or {}).items():
        path = os.path.join(repo, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
    for name in remove:
        git(repo, "rm", "-q", name)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def test_restrict_delta_keeps_only_changed_files():
    from discovery_common.mapping import restrict_delta

    rec = lambda file: SimpleNamespace(file=file)     # noqa: E731
    k = [uuid.uuid4() for _ in range(5)]
    delta = [("added", k[0], rec("/api/users.proto")), ("modified", k[1], rec("/api/orders.proto")),
             ("removed", k[2], None), ("removed", k[3], None), ("added", k[4], rec(None))]
    kept = restrict_delta(delta, {"api/users.proto", "api/gone.proto"},
                          {k[2]: "/api/gone.proto", k[3]: "/api/pay.proto"})
    assert [key for _, key, _ in kept] == [k[0], k[2], k[4]]       # unknown file: kept


def test_changed_files_are_vs_merge_base_not_target_head(scanner, monkeypatch, tmp_path):
    gl_service = scanner.use_real("services.gl_service")

    origin = str(tmp_path / "origin")
    os.makedirs(origin)
    git(origin, "init", "-q", "-b", "master")
    commit_files(origin, "base", {"api/users.proto": "u1", "api/orders.proto": "o1", "api/old.proto": "x"})
    git(origin, "checkout", "-q", "-b", "feature")
    source = commit_files(origin, "mr change", {"api/users.proto": "u2", "api/new.proto": "n"}, remove=["api/old.proto"])
    git(origin, "checkout", "-q", "master")
    # the target moves on after the fork: none of this is an MR change
    target = commit_files(origin, "target change", {"api/orders.proto": "o2", "api/pay.proto": "p"})

    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    checkout = os.path.join("code", "1", "20", source)
    git(str(work), "clone", "-q", "--branch", "feature", "--single-branch", origin, checkout)

    changed = gl_service.get_mr_changed_files(1, 20, source, "master", target)
    assert changed == {"api/users.proto", "api/new.proto", "api/old.proto"}

    # target commit unknown in the remote (force push): falls back to the fetched head
    assert gl_service.get_mr_changed_files(1, 20, source, "master", "0" * 40) == changed


def test_changed_files_unknown_without_git_checkout(scanner, monkeypatch, tmp_path):
    gl_service = scanner.use_real("services.gl_service")
    monkeypatch.chdir(tmp_path)
    os.makedirs(os.path.join("code", "1", "20", "abc"))
    assert gl_service.get_mr_changed_files(1, 20, "abc", "master", "def") is None
