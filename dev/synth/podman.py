"""Synthetic Kubernetes audit event generator (podman/k8s e2e harness).

The ``victorialogs_podman`` pipeline applies to ``product: kubernetes``
rules; the public SigmaHQ corpus that uses container fields lives under
``rules/application/kubernetes/audit/`` and queries top-level/nested
audit-event fields (``verb``, ``objectRef.resource``,
``objectRef.subresource``, ``objectRef.namespace``,
``objectRef.apiGroup``, ``responseStatus.code``, ``capabilities``,
``hostPath``, ``apiGroup``). None of those are renamed by the podman
field mapping, which makes them ideal for a one-shot ingest test:
synthetic events emit those fields directly, the converted Sigma rule
queries them as-is.

Two generators are exposed:

* ``generate`` (registered as ``podman``) — mixed traffic, ~60% benign
  and ~40% attack. Each attack branch plants verbatim selectors that
  public Kubernetes audit Sigma rules look for, so the e2e harness has
  reliable positive expectations to assert against.
* ``generate_benign`` (registered as ``podman_benign``) — benign-only
  traffic. Used for negative expectations: rules that fire on the attack
  dataset MUST NOT fire here.

All identifying values come from ``_vocab``; no real cluster names,
namespaces, or service accounts.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from typing import Any

from . import _vocab
from ._time import stamp

_BENIGN_NAMESPACES = ("default", "app-prod", "app-staging", "monitoring", "logging")
_BENIGN_RESOURCES = (
    ("pods", "get"),
    ("pods", "list"),
    ("services", "list"),
    ("configmaps", "get"),
    ("deployments", "get"),
    ("deployments", "list"),
    ("nodes", "get"),
)

_BENIGN_USERS = ("system:serviceaccount:default:web", "system:serviceaccount:monitoring:prom")


def _benign(rng: random.Random) -> dict[str, Any]:
    resource, verb = rng.choice(_BENIGN_RESOURCES)
    namespace = rng.choice(_BENIGN_NAMESPACES)
    return {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "verb": verb,
        "user": {"username": rng.choice(_BENIGN_USERS)},
        "sourceIPs": [_vocab.random_rfc1918_v4(rng)],
        "objectRef": {
            "resource": resource,
            "namespace": namespace,
            "apiGroup": "" if resource in ("pods", "services", "configmaps") else "apps",
        },
        "apiGroup": "",
        "responseStatus": {"code": 200, "metadata": {}},
        "stage": "ResponseComplete",
    }


# ---------------------- attack branches (verbatim selectors) -----------------
#
# Each branch plants a complete event matching the named k8s-audit Sigma
# rule. Branch -> covered rule:
#
#   exec_into_pod      -> kubernetes_audit_exec_into_container.yml
#   privileged_pod     -> kubernetes_audit_privileged_pod_creation.yml
#   system_namespace   -> kubernetes_audit_pod_in_system_namespace.yml
#   secrets_enum       -> kubernetes_audit_secrets_enumeration.yml
#   serviceaccount     -> kubernetes_audit_serviceaccount_creation.yml
#   hostpath_mount     -> kubernetes_audit_hostpath_mount.yml
#   sidecar_injection  -> kubernetes_audit_sidecar_injection.yml
#   unauth_action      -> kubernetes_audit_unauthorized_unauthenticated_actions.yml
#   admission_modify   -> kubernetes_audit_change_admission_controller.yml
#   events_deleted     -> kubernetes_audit_events_deleted.yml


def _attack_branch(rng: random.Random) -> dict[str, Any]:
    branch = rng.choice(
        (
            "exec_into_pod",
            "privileged_pod",
            "system_namespace",
            "secrets_enum",
            "serviceaccount",
            "hostpath_mount",
            "sidecar_injection",
            "unauth_action",
            "admission_modify",
            "events_deleted",
        )
    )
    user = {"username": f"system:serviceaccount:default:{_vocab.random_username(rng)}"}
    src_ip = [_vocab.random_rfc1918_v4(rng)]
    base: dict[str, Any] = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "user": user,
        "sourceIPs": src_ip,
        "stage": "ResponseComplete",
    }

    if branch == "exec_into_pod":
        base.update(
            {
                "verb": "create",
                "objectRef": {
                    "resource": "pods",
                    "subresource": "exec",
                    "namespace": "default",
                    "apiGroup": "",
                },
                "apiGroup": "",
                "responseStatus": {"code": 101, "metadata": {}},
            }
        )
    elif branch == "privileged_pod":
        base.update(
            {
                "verb": "create",
                "objectRef": {
                    "resource": "pods",
                    "namespace": rng.choice(_BENIGN_NAMESPACES),
                    "apiGroup": "",
                },
                "apiGroup": "",
                "capabilities": [rng.choice(("SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"))],
                "responseStatus": {"code": 201, "metadata": {}},
            }
        )
    elif branch == "system_namespace":
        base.update(
            {
                "verb": "create",
                "objectRef": {
                    "resource": "pods",
                    "namespace": "kube-system",
                    "apiGroup": "",
                },
                "apiGroup": "",
                "responseStatus": {"code": 201, "metadata": {}},
            }
        )
    elif branch == "secrets_enum":
        base.update(
            {
                "verb": "list",
                "objectRef": {
                    "resource": "secrets",
                    "namespace": rng.choice(_BENIGN_NAMESPACES),
                    "apiGroup": "",
                },
                "apiGroup": "",
                "responseStatus": {"code": 200, "metadata": {}},
            }
        )
    elif branch == "serviceaccount":
        base.update(
            {
                "verb": "create",
                "objectRef": {
                    "resource": "serviceaccounts",
                    "namespace": rng.choice(_BENIGN_NAMESPACES),
                    "apiGroup": "",
                },
                "apiGroup": "",
                "responseStatus": {"code": 201, "metadata": {}},
            }
        )
    elif branch == "hostpath_mount":
        base.update(
            {
                "verb": "create",
                "objectRef": {
                    "resource": "pods",
                    "namespace": rng.choice(_BENIGN_NAMESPACES),
                    "apiGroup": "",
                },
                "apiGroup": "",
                # Public k8s-audit rule asserts `hostPath: '*'` — exists check.
                # VL flattens nested JSON to dotted paths, so a top-level
                # scalar (rather than {"path": ...}) is what `hostPath:*`
                # actually matches against. Keeps semantic intent of the rule.
                "hostPath": rng.choice(("/etc", "/var/run", "/var/lib/docker")),
                "responseStatus": {"code": 201, "metadata": {}},
            }
        )
    elif branch == "sidecar_injection":
        base.update(
            {
                "verb": "patch",
                "objectRef": {
                    "resource": "deployments",
                    "namespace": rng.choice(_BENIGN_NAMESPACES),
                    "apiGroup": "apps",
                },
                "apiGroup": "apps",
                "responseStatus": {"code": 200, "metadata": {}},
            }
        )
    elif branch == "unauth_action":
        base.update(
            {
                "verb": rng.choice(("get", "list", "watch")),
                "objectRef": {
                    "resource": rng.choice(("pods", "secrets", "configmaps")),
                    "namespace": rng.choice(_BENIGN_NAMESPACES),
                    "apiGroup": "",
                },
                "apiGroup": "",
                "responseStatus": {"code": rng.choice((401, 403)), "metadata": {}},
            }
        )
    elif branch == "admission_modify":
        base.update(
            {
                "verb": rng.choice(("create", "update", "patch", "delete", "replace")),
                "objectRef": {
                    "resource": rng.choice(
                        ("mutatingwebhookconfigurations", "validatingwebhookconfigurations")
                    ),
                    "namespace": "",
                    "apiGroup": "admissionregistration.k8s.io",
                },
                "apiGroup": "admissionregistration.k8s.io",
                "responseStatus": {"code": 200, "metadata": {}},
            }
        )
    else:  # events_deleted
        base.update(
            {
                "verb": "delete",
                "objectRef": {
                    "resource": "events",
                    "namespace": rng.choice(_BENIGN_NAMESPACES),
                    "apiGroup": "",
                },
                "apiGroup": "",
                "responseStatus": {"code": 200, "metadata": {}},
            }
        )

    return base


def _event(rng: random.Random, offset: int, *, attack: bool) -> dict[str, Any]:
    ev = _attack_branch(rng) if attack else _benign(rng)
    ev["_time"] = stamp(offset)
    return ev


def generate(seed: int, count: int) -> Iterator[dict[str, Any]]:
    """Yield ``count`` synthetic Kubernetes audit events seeded by ``seed``.

    ~40% of events are attack-shaped, distributed across the branches
    above so a 5000-event run plants ~200 of each pattern.
    """
    rng = random.Random(seed)
    for i in range(count):
        attack = rng.random() < 0.40
        yield _event(rng, i, attack=attack)


def generate_benign(seed: int, count: int) -> Iterator[dict[str, Any]]:
    """Yield ``count`` benign-only Kubernetes audit events.

    Used for negative e2e expectations — k8s-audit Sigma rules that fire
    on the attack-mix dataset MUST NOT fire here.
    """
    rng = random.Random(seed)
    for i in range(count):
        yield _event(rng, i, attack=False)
