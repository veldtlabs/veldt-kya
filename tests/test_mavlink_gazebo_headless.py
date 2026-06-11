"""Unit tests for the Gazebo capture script's docker-args assembly.

The script lives in ``scripts/mavlink_gazebo_sitl_capture.py`` and
runs Docker under the hood. We don't actually launch Gazebo here;
we mock ``subprocess.run`` and assert the docker argv list has the
right shape for each branch:

* HEADLESS=1 -> no X11 mount, no GPU device, ``gazebo --no-gui``
  trailing args.
* HEADLESS unset -> X11 mount + (when /dev/dri exists) GPU device,
  no trailing gazebo args.

These branches are easy to silently break (one missed env-var
check or an OS-specific branch flipping the wrong way) and never
exercised in CI without Docker. The mock catches regressions
cheaply.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_SCRIPT = Path(__file__).parent.parent / "scripts" / "mavlink_gazebo_sitl_capture.py"


def _import_gazebo_module(env_overrides: dict[str, str] | None = None):
    """Import the Gazebo capture script as a module with a clean
    env. The script reads env vars at module load time, so we
    need to patch them BEFORE the import."""
    # Save + restore the env so this fixture is isolation-safe.
    import os
    saved: dict[str, str | None] = {}
    keys = [
        "OUT", "TIMEOUT", "MISSION", "MAVLINK_PORT",
        "KYA_GAZEBO_HEADLESS", "GAZEBO_IMAGE",
        # Pop the container-name overrides so a stale env var from
        # another test or the user's shell can't bleed into the
        # docker-argv assertion. Even though the live SITL var is
        # not consumed by the Gazebo script today, a future port
        # of the hardening would silently fail without this.
        "KYA_SITL_CONTAINER", "KYA_GAZEBO_CONTAINER",
    ]
    for k in keys:
        saved[k] = os.environ.get(k)
        os.environ.pop(k, None)
    for k, v in (env_overrides or {}).items():
        os.environ[k] = v
    # Drop a cached import so module-level code re-runs with new env.
    sys.modules.pop("_gazebo_script", None)
    try:
        spec = importlib.util.spec_from_file_location(
            "_gazebo_script", _SCRIPT,
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_gazebo_script"] = mod
        spec.loader.exec_module(mod)
        return mod
    finally:
        # Restore env so other tests don't see our overrides.
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ── Shared mock harness ──────────────────────────────────────────


def _captured_docker_argv(env_overrides: dict[str, str]) -> list[str]:
    """Import the script under the given env, patch subprocess.run,
    invoke launch_gazebo_sitl, and return the captured docker
    argv list. Patches:
      * subprocess.run -> returncode=0 stub (so launch_gazebo_sitl
        thinks the container started)
      * cleanup_container -> no-op
      * _allow_x11_to_docker -> no-op (don't touch real xhost)
    """
    mod = _import_gazebo_module(env_overrides)

    captured_args: list[list[str]] = []

    def _fake_run(*args, **kwargs):
        # The script's _sitl_common.run() calls subprocess.run.
        # Capture the cmd list -- args[0] is the cmd argv when
        # called positionally.
        if args:
            captured_args.append(list(args[0]))
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        return result

    with patch("subprocess.run", side_effect=_fake_run), \
         patch.object(mod, "cleanup_container"), \
         patch.object(mod, "cleanup_stale_kya_containers"), \
         patch.object(mod, "verify_host_port_free"), \
         patch.object(mod, "verify_container_running"), \
         patch.object(mod, "_allow_x11_to_docker"):
        mod.launch_gazebo_sitl()

    # Find the `docker run` invocation specifically.
    for argv in captured_args:
        if argv[:2] == ["docker", "run"]:
            return argv
    raise AssertionError(
        f"no `docker run` argv captured; got {captured_args}")


# ── Tests ───────────────────────────────────────────────────────


class TestHeadlessGazebo:
    """KYA_GAZEBO_HEADLESS=1 disables rendering AND skips X11 mount."""

    def test_no_gui_trailing_args_present(self):
        argv = _captured_docker_argv({"KYA_GAZEBO_HEADLESS": "1"})
        # The script appends ["gazebo", "--verbose", "--no-gui"]
        # after the image when HEADLESS.
        assert "--no-gui" in argv, (
            f"HEADLESS=1 must produce --no-gui in docker argv; "
            f"got {argv}")
        assert "--verbose" in argv

    def test_no_x11_socket_mount(self):
        argv = _captured_docker_argv({"KYA_GAZEBO_HEADLESS": "1"})
        joined = " ".join(argv)
        # X11 socket mount must NOT appear in headless mode.
        assert "/tmp/.X11-unix" not in joined, (
            f"HEADLESS=1 must not mount /tmp/.X11-unix; got {argv}")

    def test_no_dri_device(self):
        argv = _captured_docker_argv({"KYA_GAZEBO_HEADLESS": "1"})
        # GPU device must NOT appear in headless mode.
        assert "/dev/dri" not in " ".join(argv), (
            f"HEADLESS=1 must not pass --device /dev/dri; got {argv}")

    def test_no_display_env(self):
        argv = _captured_docker_argv({"KYA_GAZEBO_HEADLESS": "1"})
        # DISPLAY env var must NOT be injected.
        assert "DISPLAY=" not in " ".join(argv)

    @pytest.mark.parametrize("truthy", [
        "1", "true", "yes", "on", "TRUE", "True", "YES",
    ])
    def test_headless_truthy_values_accepted(self, truthy):
        argv = _captured_docker_argv({"KYA_GAZEBO_HEADLESS": truthy})
        assert "--no-gui" in argv, (
            f"KYA_GAZEBO_HEADLESS={truthy!r} should enable headless; "
            f"got argv={argv}")


class TestVisibleGazebo:
    """HEADLESS unset on Linux mounts X11 + (when available) GPU.

    The script branches on sys.platform == "linux". On the CI
    runners (Linux), this branch fires. On Windows / macOS dev
    machines running this test suite the branch is skipped --
    we don't get a meaningful assertion. Mark accordingly.
    """

    @pytest.mark.skipif(
        sys.platform != "linux",
        reason="visible branch only runs on Linux hosts",
    )
    def test_x11_socket_mount_present(self):
        argv = _captured_docker_argv({})
        assert "/tmp/.X11-unix:/tmp/.X11-unix" in argv, (
            f"visible mode on Linux must mount X11; got {argv}")

    @pytest.mark.skipif(
        sys.platform != "linux",
        reason="visible branch only runs on Linux hosts",
    )
    def test_no_gui_trailing_args_absent(self):
        argv = _captured_docker_argv({})
        assert "--no-gui" not in argv, (
            f"visible mode must NOT pass --no-gui; got {argv}")

    @pytest.mark.skipif(
        sys.platform != "linux",
        reason="visible branch only runs on Linux hosts",
    )
    def test_display_env_set(self):
        argv = _captured_docker_argv({})
        joined = " ".join(argv)
        assert "DISPLAY=" in joined, (
            f"visible mode must set DISPLAY env; got {argv}")


class TestPortBinding:
    """Both branches must bind the MAVLink port to loopback only."""

    def test_headless_binds_loopback(self):
        argv = _captured_docker_argv({"KYA_GAZEBO_HEADLESS": "1"})
        joined = " ".join(argv)
        assert "127.0.0.1:14550:14550/udp" in joined, (
            f"port must be bound to 127.0.0.1, not 0.0.0.0; "
            f"got {argv}")

    def test_custom_port_honoured(self):
        argv = _captured_docker_argv({
            "KYA_GAZEBO_HEADLESS": "1",
            "MAVLINK_PORT": "14551",
        })
        joined = " ".join(argv)
        assert "127.0.0.1:14551:14550/udp" in joined, (
            f"MAVLINK_PORT env override must change the host bind; "
            f"got {argv}")


class TestImageOverride:
    """GAZEBO_IMAGE env can swap the container image."""

    def test_default_image_used(self):
        argv = _captured_docker_argv({"KYA_GAZEBO_HEADLESS": "1"})
        assert "khancyr/ardupilot-gazebo:latest" in argv

    def test_override_image_used(self):
        argv = _captured_docker_argv({
            "KYA_GAZEBO_HEADLESS": "1",
            "GAZEBO_IMAGE": "vendor/custom-gazebo:v1.0",
        })
        assert "vendor/custom-gazebo:v1.0" in argv
        # And the default is NOT included
        assert "khancyr/ardupilot-gazebo:latest" not in argv


# ── Shared module behaviour (env_int + preflight + atexit) ───────


class TestEnvIntValidation:
    """Day-4.5 follow-up review fix: env_int rejects non-positive
    values rather than letting the capture loop silently skip."""

    def test_negative_timeout_rejected(self):
        import os
        import subprocess
        os.environ["TIMEOUT"] = "-5"
        try:
            result = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, 'scripts'); "
                 "from _sitl_common import env_int; "
                 "env_int('TIMEOUT', 120)"],
                capture_output=True, text=True, timeout=10,
            )
            assert result.returncode != 0
            assert "positive" in result.stderr.lower()
        finally:
            os.environ.pop("TIMEOUT", None)

    def test_zero_mission_rejected(self):
        import os
        import subprocess
        os.environ["MISSION"] = "0"
        try:
            result = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, 'scripts'); "
                 "from _sitl_common import env_int; "
                 "env_int('MISSION', 30)"],
                capture_output=True, text=True, timeout=10,
            )
            assert result.returncode != 0
            assert "positive" in result.stderr.lower()
        finally:
            os.environ.pop("MISSION", None)

    def test_non_integer_rejected(self):
        import os
        import subprocess
        os.environ["TIMEOUT"] = "abc"
        try:
            result = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, 'scripts'); "
                 "from _sitl_common import env_int; "
                 "env_int('TIMEOUT', 120)"],
                capture_output=True, text=True, timeout=10,
            )
            assert result.returncode != 0
            assert "not an integer" in result.stderr.lower()
        finally:
            os.environ.pop("TIMEOUT", None)

    def test_positive_int_accepted(self):
        """The happy path -- valid positive integer flows through."""
        import os
        os.environ["TIMEOUT"] = "180"
        try:
            sys.path.insert(0, str(_SCRIPT.parent))
            from _sitl_common import env_int
            assert env_int("TIMEOUT", 120) == 180
        finally:
            os.environ.pop("TIMEOUT", None)
            try:
                sys.path.remove(str(_SCRIPT.parent))
            except ValueError:
                pass


class TestEnvPortValidation:
    """Review fix for H3: env_port adds an upper-bound check that
    env_int alone doesn't enforce. Without it, MAVLINK_PORT=99999
    would burn ~3 min on a wasted image pull before docker run
    rejected the bind. env_port catches it in microseconds."""

    def test_port_above_max_rejected(self):
        import os
        import subprocess
        os.environ["MAVLINK_PORT"] = "99999"
        try:
            result = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, 'scripts'); "
                 "from _sitl_common import env_port; "
                 "env_port('MAVLINK_PORT', 14550)"],
                capture_output=True, text=True, timeout=10,
            )
            assert result.returncode != 0
            assert "65535" in result.stderr
        finally:
            os.environ.pop("MAVLINK_PORT", None)

    def test_port_at_max_accepted(self):
        """Boundary: 65535 must pass."""
        import os
        os.environ["MAVLINK_PORT"] = "65535"
        try:
            sys.modules.pop("_sitl_common", None)
            sys.path.insert(0, str(_SCRIPT.parent))
            from _sitl_common import env_port  # noqa: PLC0415
            assert env_port("MAVLINK_PORT", 14550) == 65535
        finally:
            os.environ.pop("MAVLINK_PORT", None)
            try:
                sys.path.remove(str(_SCRIPT.parent))
            except ValueError:
                pass

    def test_port_zero_rejected(self):
        """Inherits env_int's positive-only check -- 0 must fail."""
        import os
        import subprocess
        os.environ["MAVLINK_PORT"] = "0"
        try:
            result = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, 'scripts'); "
                 "from _sitl_common import env_port; "
                 "env_port('MAVLINK_PORT', 14550)"],
                capture_output=True, text=True, timeout=10,
            )
            assert result.returncode != 0
            assert "positive" in result.stderr.lower()
        finally:
            os.environ.pop("MAVLINK_PORT", None)


class TestStaleSweepPrefixAnchor:
    """Review fix for HIGH: docker ps name-filter is SUBSTRING.
    Without post-filtering, a user's adjacent container like
    ``my-kya-mavlink-sitl-debug`` would be reaped. Anchor on
    ``startswith(prefix + "-")`` is required."""

    def _run_sweep_with_mock_listing(self, listing_stdout: str,
                                     now_unix: float,
                                     prefix: str = "kya-mavlink-sitl"):
        """Patch subprocess.run so cleanup_stale_kya_containers
        sees the given docker-ps listing and we capture which
        names ended up in docker rm calls."""
        sys.modules.pop("_sitl_common", None)
        sys.path.insert(0, str(_SCRIPT.parent))
        from _sitl_common import (  # noqa: PLC0415
            cleanup_stale_kya_containers,
        )
        removed: list[str] = []

        def _fake_run(cmd, *args, **kwargs):
            r = MagicMock()
            r.returncode = 0
            r.stderr = ""
            # docker ps -a --filter ... --format ... -> listing
            if (isinstance(cmd, list) and len(cmd) >= 2
                    and cmd[:2] == ["docker", "ps"]):
                r.stdout = listing_stdout
                return r
            # docker rm -f <name>
            if (isinstance(cmd, list) and len(cmd) >= 3
                    and cmd[:3] == ["docker", "rm", "-f"]):
                removed.append(cmd[3])
                r.stdout = b""
                return r
            r.stdout = ""
            return r

        with patch("_sitl_common.subprocess.run",
                   side_effect=_fake_run), \
             patch("_sitl_common.time.time", return_value=now_unix):
            cleanup_stale_kya_containers(
                prefix=prefix, max_age_minutes=60,
            )
        try:
            sys.path.remove(str(_SCRIPT.parent))
        except ValueError:
            pass
        return removed

    # Helper: parse a docker-ps CreatedAt to a unix timestamp so
    # tests can pick "now" as an exact offset. Using a hardcoded
    # epoch is fragile and we got it wrong on the first attempt.
    @staticmethod
    def _listing_time(created_at: str) -> float:
        # Strip trailing tz-name (e.g. " UTC") -- keep the +0000.
        import re
        from datetime import datetime
        cleaned = re.sub(r"\s+[A-Z]{1,4}$", "", created_at.strip())
        return datetime.strptime(
            cleaned, "%Y-%m-%d %H:%M:%S %z",
        ).timestamp()

    def test_substring_match_NOT_reaped(self):
        """The bug the review found: 'my-kya-mavlink-sitl-debug'
        would match a substring filter but is NOT one of ours."""
        created_at = "2026-06-01 22:42:58 +0000 UTC"
        listing = (
            f"my-kya-mavlink-sitl-debug\t{created_at}\tabc123def456\n"
        )
        # 70 minutes after the listed CreatedAt -> well over the
        # 60-min sweep threshold.
        now_unix = self._listing_time(created_at) + 70 * 60
        removed = self._run_sweep_with_mock_listing(
            listing, now_unix=now_unix,
        )
        assert "my-kya-mavlink-sitl-debug" not in removed, (
            "stale-sweep substring match crossed the prefix "
            "anchor and would have killed a user's adjacent "
            "container -- prefix-anchor fix regressed.")

    def test_legit_prefixed_container_reaped(self):
        """The intended case: 'kya-mavlink-sitl-<pid>' that's
        an hour old should be removed."""
        created_at = "2026-06-01 22:42:58 +0000 UTC"
        listing = (
            f"kya-mavlink-sitl-12345\t{created_at}\tdef456abc789\n"
        )
        now_unix = self._listing_time(created_at) + 70 * 60
        removed = self._run_sweep_with_mock_listing(
            listing, now_unix=now_unix,
        )
        assert "kya-mavlink-sitl-12345" in removed, (
            "stale-sweep failed to reap a legitimately-stale "
            "PID-tagged container; prefix anchor is too tight.")

    def test_fresh_container_NOT_reaped(self):
        """A parallel-running invocation's container is YOUNG
        -- never reap a live sibling run."""
        created_at = "2026-06-01 23:40:00 +0000 UTC"
        listing = (
            f"kya-mavlink-sitl-67890\t{created_at}\tfedcba654321\n"
        )
        # 2 minutes after listed -- well under the 60-min threshold.
        now_unix = self._listing_time(created_at) + 2 * 60
        removed = self._run_sweep_with_mock_listing(
            listing, now_unix=now_unix,
        )
        assert "kya-mavlink-sitl-67890" not in removed, (
            "stale-sweep killed a young container; age threshold "
            "(60 min) is broken or being ignored.")


class TestDockerDaemonPreflight:
    """preflight() reports a friendly error when the Docker daemon
    isn't reachable, rather than letting the bare TimeoutExpired
    or non-zero exit code surface as a noisy traceback."""

    def test_docker_info_failure_calls_die(self):
        sys.path.insert(0, str(_SCRIPT.parent))
        try:
            # Force a clean re-import so the module's `subprocess`
            # reference is the same object we're going to patch.
            sys.modules.pop("_sitl_common", None)
            from _sitl_common import preflight  # noqa: PLC0415

            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_result.stdout = b""
            mock_result.stderr = b"Cannot connect to the Docker daemon"

            from pathlib import Path
            tmp = Path("/tmp/_sitl_preflight_probe.json")
            tmp.parent.mkdir(parents=True, exist_ok=True)

            # __import__ patch keeps pymavlink check happy
            # without requiring the real package.
            with (
                patch("_sitl_common.shutil.which",
                      return_value="/usr/bin/docker"),
                patch("_sitl_common.subprocess.run",
                      return_value=mock_result),
                patch("builtins.__import__"),
                pytest.raises(SystemExit) as exc_info,
            ):
                preflight(tmp)
            assert exc_info.value.code == 1
        finally:
            try:
                sys.path.remove(str(_SCRIPT.parent))
            except ValueError:
                pass
