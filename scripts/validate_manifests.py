"""Validate the CI workflow and the compose files against their public schemas.

Useful before the first push (a typo in ci.yml otherwise costs a broken
pipeline) and before Docker is installed (`docker compose config` is the other
way to check the compose files).

    python scripts/validate_manifests.py

Requires `jsonschema` (in requirements-dev.txt) and network access to
schemastore.org / raw.githubusercontent.com.
"""
import json
import pathlib
import re
import sys
import urllib.request

import yaml
from jsonschema import Draft7Validator

WF_SCHEMA = "https://json.schemastore.org/github-workflow.json"
COMPOSE_SCHEMA = ("https://raw.githubusercontent.com/compose-spec/compose-spec/"
                  "master/schema/compose-spec.json")


class WorkflowLoader(yaml.SafeLoader):
    """YAML 1.1 turns the key `on:` into the boolean True.

    GitHub treats `on` as a plain string, so restrict bool inference to
    true/false only; otherwise the schema sees a boolean key and reports
    "additionalProperties" plus a missing 'on'.
    """


WorkflowLoader.yaml_implicit_resolvers = {
    key: [(tag, regexp) for tag, regexp in value
          if tag != "tag:yaml.org,2002:bool"]
    for key, value in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


def load_yaml(path: pathlib.Path):
    with path.open(encoding="utf-8") as fh:
        return yaml.load(fh, Loader=WorkflowLoader)


def fetch(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def validate(schema: dict, document, label: str) -> int:
    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    if not errors:
        print(f"OK    {label}")
        return 0
    print(f"FAIL  {label}")
    for err in errors[:12]:
        print(f"        {'/'.join(map(str, err.path)) or '<root>'}: {err.message[:180]}")
    print(f"        ({len(errors)} error(s))")
    return 1


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    status = 0

    wf_schema = fetch(WF_SCHEMA)
    for path in sorted((root / ".github/workflows").glob("*.yml")):
        doc = load_yaml(path)
        status |= validate(wf_schema, doc, str(path.relative_to(root)).replace("\\", "/"))

    compose_schema = fetch(COMPOSE_SCHEMA)
    for name in ("cve/docker-compose.yml", "cve/docker-compose.fixed.yml"):
        doc = load_yaml(root / name)
        status |= validate(compose_schema, doc, name)

    return status


if __name__ == "__main__":
    sys.exit(main())
