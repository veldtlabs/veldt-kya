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
from unittest.mock import patch, MagicMock

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

            with patch("_sitl_common.shutil.which", return_value="/usr/bin/docker"), \
                 patch("_sitl_common.subprocess.run", return_value=mock_result), \
                 patch("builtins.__import__"):
                # __import__ patch keeps pymavlink check happy
                # without requiring the real package.
                with pytest.raises(SystemExit) as exc_info:
                    preflight(tmp)
            assert exc_info.value.code == 1
        finally:
            try:
                sys.path.remove(str(_SCRIPT.parent))
            except ValueError:
                pass
