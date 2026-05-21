"""Local validator for the sdk-build.yml workflow. Parses the YAML and
prints the step graph so we can confirm structure before pushing."""

import sys

import yaml

WF = "/repo/.github/workflows/sdk-build.yml"


def main():
    with open(WF) as f:
        try:
            wf = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            print(f"YAML ERROR: {exc}")
            sys.exit(1)

    print(f"workflow name : {wf.get('name')}")
    triggers = wf.get(True, wf.get("on"))  # PyYAML parses bare `on:` as True
    if isinstance(triggers, dict):
        print(f"triggers      : {list(triggers.keys())}")

    jobs = wf.get("jobs", {})
    for jname, job in jobs.items():
        print()
        print(f"job: {jname}")
        print(f"  runs-on    : {job.get('runs-on')}")
        print(f"  timeout    : {job.get('timeout-minutes')} min")
        services = job.get("services") or {}
        if services:
            print(f"  services   : {list(services.keys())}")
        envs = job.get("env") or {}
        if envs:
            print(f"  env keys   : {list(envs.keys())}")
        steps = job.get("steps") or []
        print(f"  steps ({len(steps)}):")
        for i, s in enumerate(steps, 1):
            label = s.get("name") or s.get("uses") or "?"
            print(f"    {i:2d}. {label}")


if __name__ == "__main__":
    main()
