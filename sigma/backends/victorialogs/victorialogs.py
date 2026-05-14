"""
pySigma → VictoriaLogs (LogsQL) backend.

See docs/mapping.md for the canonical Sigma → LogsQL specification and
docs/architecture.md for the rationale behind every override below.
LogsQL reference: https://docs.victoriametrics.com/victorialogs/logsql/
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any, ClassVar

import yaml
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
)
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaTypeError
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

_VMALERT_ALERT_NAME_RE = re.compile(r"[^A-Za-z0-9_]+")

# Sigma `level` → Grafana `labels.severity`. Critical/high are operator-actionable
# (`critical`/`warning`); medium and below collapse to `info` because Grafana's
# Alertmanager routing typically only groups on these three buckets.
_GRAFANA_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "warning",
    "medium": "info",
    "low": "info",
    "informational": "info",
}

# VictoriaLogs datasource plugin queryType for the `/select/logsql/stats_query`
# endpoint. Source: VictoriaMetrics/victorialogs-datasource src/types.ts:40 at
# commit f487c5b6124cc7ff89bb10620e0c525e7e576041. Alert evaluation is
# point-in-time, so we use the non-range stats endpoint.
_VL_PLUGIN_QUERY_TYPE_STATS = "stats"
_VL_PLUGIN_DATASOURCE_TYPE = "victoriametrics-logs-datasource"

# Grafana server-side expression datasource. Reserved UID per Grafana docs.
_GRAFANA_EXPR_DS_UID = "__expr__"


class VictoriaLogsBackend(TextQueryBackend):
    """Emit LogsQL queries from Sigma rules."""

    name: ClassVar[str] = "VictoriaLogs LogsQL backend"
    formats: ClassVar[dict[str, str]] = {
        "default": "Plain LogsQL queries",
        "vmalert": "vmalert rule group YAML (type: vlogs) for VictoriaLogs",
        "grafana_alerting": (
            "Grafana Alerting provisioning YAML (apiVersion: 1) for the "
            "victoriametrics-logs-datasource plugin"
        ),
    }
    requires_pipeline: ClassVar[bool] = False

    def __init__(
        self,
        *args: Any,
        grafana_datasource_uid: str = "victorialogs",
        grafana_folder: str = "sigma",
        grafana_org_id: int = 1,
        grafana_interval: str = "1m",
        grafana_relative_time_from: int = 600,
        **kwargs: Any,
    ) -> None:
        """Backend with optional Grafana Alerting config.

        The Grafana parameters only affect the ``grafana_alerting`` output
        format. ``grafana_datasource_uid`` must match the UID configured for
        the VictoriaLogs datasource in the target Grafana install (set via
        `-O grafana_datasource_uid=<uid>` on the CLI). The placeholder default
        keeps the emitted YAML valid but will not load until the operator
        substitutes the real UID.
        """
        super().__init__(*args, **kwargs)
        self.grafana_datasource_uid = grafana_datasource_uid
        self.grafana_folder = grafana_folder
        self.grafana_org_id = grafana_org_id
        self.grafana_interval = grafana_interval
        self.grafana_relative_time_from = grafana_relative_time_from

    precedence: ClassVar[tuple[type[ConditionItem], type[ConditionItem], type[ConditionItem]]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[str] = "({expr})"

    # Boolean tokens — see docs/mapping.md §2.
    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = ":="

    # Field-name quoting — see docs/mapping.md §3.
    field_quote: ClassVar[str] = '"'
    field_quote_pattern: ClassVar[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
    field_quote_pattern_negation: ClassVar[bool] = True

    field_escape: ClassVar[str] = "\\"
    field_escape_quote: ClassVar[bool] = True
    field_escape_pattern: ClassVar[re.Pattern[str]] = re.compile(r'["\\]')

    # Value quoting / escape rules — see docs/mapping.md §4.
    # `wildcard_single` stays declared (not None) so pySigma routes `?`-bearing
    # values through the regex template; see docs/limitations.md.
    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "?"
    add_escaped: ClassVar[str] = "\\"
    filter_chars: ClassVar[str] = ""
    bool_values: ClassVar[dict[bool, str | None]] = {True: "true", False: "false"}

    # String-shape operators — see docs/mapping.md §5. `_allow_special: False`
    # forces values with extra special chars onto wildcard_match_expression.
    startswith_expression: ClassVar[str] = "{field}:={value}*"
    startswith_expression_allow_special: ClassVar[bool] = False
    endswith_expression: ClassVar[str] = '{field}:~"{regex}$"'
    endswith_expression_allow_special: ClassVar[bool] = False
    # `{value}` is pre-quoted by convert_value_str — do not re-quote here.
    contains_expression: ClassVar[str] = "{field}:{value}"
    contains_expression_allow_special: ClassVar[bool] = False
    wildcard_match_expression: ClassVar[str] = '{field}:~"{regex}"'

    # Regex — see docs/mapping.md §6. type: ignore mirrors Loki: pysigma
    # annotates re_escape as list[str] but its own backends declare it as a tuple.
    re_expression: ClassVar[str] = '{field}:~"{regex}"'
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[tuple[str, ...]] = ('"',)  # type: ignore[assignment]
    re_escape_escape_char: bool = True
    re_flag_prefix = True
    re_flags = {  # noqa: RUF012
        SigmaRegularExpressionFlag.IGNORECASE: "i",
        SigmaRegularExpressionFlag.MULTILINE: "m",
        SigmaRegularExpressionFlag.DOTALL: "s",
    }

    # Case-sensitive matching — `:=` is already case-sensitive (LogsQL default).
    case_sensitive_match_expression: ClassVar[str] = "{field}:={value}"
    case_sensitive_startswith_expression: ClassVar[str] = "{field}:={value}*"
    case_sensitive_contains_expression: ClassVar[str] = "{field}:{value}"

    # CIDR — see docs/mapping.md §7. Family dispatch is in
    # convert_condition_field_eq_val_cidr below.
    cidr_expression: ClassVar[str] = '{field}:ipv4_range("{value}")'
    cidr_expression_ipv6: ClassVar[str] = '{field}:ipv6_range("{value}")'

    # Numeric comparison — see docs/mapping.md §8.
    compare_op_expression: ClassVar[str] = "{field}:{operator}{value}"
    compare_operators: ClassVar[dict[Any, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Field-equals-field — see docs/mapping.md §9.
    field_equals_field_expression: ClassVar[str] = "{field1}:eq_field({field2})"
    field_equals_field_escaping_quoting = (True, True)

    # Null / exists — see docs/mapping.md §10.
    field_null_expression: ClassVar[str] = '{field}:""'
    field_exists_expression: ClassVar[str] = "{field}:*"
    field_not_exists_expression: ClassVar[str] = "NOT {field}:*"

    # IN-list — see docs/mapping.md §11. AND-in has no native form; let pySigma expand.
    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[str] = "{field}:{op}({list})"
    or_in_operator: ClassVar[str] = "in"
    list_separator: ClassVar[str] = ", "

    # Unbound (keyword) values — see docs/mapping.md §12. The string value is
    # pre-quoted by convert_value_str; the regex variant gets a bare pattern.
    unbound_value_str_expression: ClassVar[str] = "{value}"
    unbound_value_num_expression: ClassVar[str] = "{value}"
    unbound_value_re_expression: ClassVar[str] = '_msg:~"{value}"'

    # Deferred sections (e.g. correlation pipes) are appended via " | ".
    deferred_start: ClassVar[str] = " | "
    deferred_separator: ClassVar[str] = " | "
    deferred_only_query: ClassVar[str] = "*"

    # ----- Correlation support — see docs/mapping.md §13. -----
    # event_count + value_count only; temporal is intentionally absent.
    correlation_methods: ClassVar[dict[str, str]] = {
        "stats": "VictoriaLogs stats-pipe correlation",
    }
    default_correlation_method: ClassVar[str] = "stats"
    default_correlation_query: ClassVar[dict[str, str]] = {
        "stats": "_time:{timespan} {search} | {aggregate} | {condition}"
    }

    correlation_search_single_rule_expression: ClassVar[str] = "{query}"

    event_count_aggregation_expression: ClassVar[dict[str, str]] = {
        "stats": "stats {groupby}count() as event_count"
    }
    value_count_aggregation_expression: ClassVar[dict[str, str]] = {
        "stats": "stats {groupby}count_uniq({field}) as value_count"
    }

    timespan_mapping: ClassVar[dict[str, str]] = {
        "s": "s",
        "m": "m",
        "h": "h",
        "d": "d",
    }

    groupby_expression: ClassVar[dict[str, str]] = {"stats": "by ({fields}) "}
    groupby_field_expression: ClassVar[dict[str, str]] = {"stats": "{field}"}
    groupby_field_expression_joiner: ClassVar[dict[str, str]] = {"stats": ", "}

    # `| filter` uses field-filter syntax (`filter cnt:>N`), not SQL-style — see docs/mapping.md §13.
    event_count_condition_expression: ClassVar[dict[str, str]] = {
        "stats": "filter event_count:{op}{count}"
    }
    value_count_condition_expression: ClassVar[dict[str, str]] = {
        "stats": "filter value_count:{op}{count}"
    }

    # ----- Custom conversion overrides -----

    def convert_condition_field_eq_val_str(
        self,
        cond: ConditionFieldEqualsValueExpression,
        state: ConversionState,
    ) -> str | DeferredQueryExpression:
        """Route Sigma `field: "*"` (any value) to field_exists_expression.

        See docs/architecture.md "Why we override convert_condition_field_eq_val_str".
        """
        value = cond.value
        if isinstance(value, SigmaString):
            parts = list(value.iter_parts())
            if parts == [SpecialChars.WILDCARD_MULTI]:
                return self.field_exists_expression.format(
                    field=self.escape_and_quote_field(cond.field)
                )
        return super().convert_condition_field_eq_val_str(cond, state)

    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        """Render a SigmaString respecting LogsQL's `:="..."` escape rules.

        Inside `:="..."` only `\\\\` and `\\"` are valid escapes; literal `*`/`?`
        must survive verbatim. See docs/architecture.md "Why we override
        convert_value_str" and docs/mapping.md §4.
        """
        if s.contains_special():
            return super().convert_value_str(s, state)
        converted = s.convert(
            escape_char=self.escape_char,
            wildcard_multi=None,
            wildcard_single=None,
            add_escaped=self.str_quote + self.add_escaped,
            filter_chars=self.filter_chars,
        )
        if self.decide_string_quoting(s):
            return self.quote_string(converted)
        return converted

    def convert_condition_field_eq_val_cidr(
        self,
        cond: ConditionFieldEqualsValueExpression,
        state: ConversionState,
    ) -> str | DeferredQueryExpression:
        """Dispatch on IPv4 vs IPv6 to pick `ipv4_range(...)` or `ipv6_range(...)`.

        See docs/architecture.md "Why we override convert_condition_field_eq_val_cidr".
        """
        cidr = cond.value
        if not isinstance(cidr, SigmaCIDRExpression):
            raise SigmaTypeError(f"Expected SigmaCIDRExpression for cond.value, got {type(cidr)}")
        template = (
            self.cidr_expression_ipv6
            if isinstance(cidr.network, ipaddress.IPv6Network)
            else self.cidr_expression
        )
        return template.format(
            field=cond.field,
            value=str(cidr.network),
            network=cidr.network.network_address,
            prefixlen=cidr.network.prefixlen,
            netmask=cidr.network.netmask,
        )

    # ----- vmalert output format — see docs/mapping.md §14. -----

    def finalize_query_vmalert(
        self,
        rule: SigmaRule,
        query: str,
        _index: int,
        state: ConversionState,
    ) -> dict[str, Any]:
        """Render one Sigma rule as a vmalert rule dict (type: vlogs).

        vmalert evaluates LogsQL via /select/logsql/stats_query{,_range}, which
        only returns metric series — so the expression must contain a `stats`
        pipe. We wrap raw selectors as `<query> | stats count() as matches |
        filter matches:>0`; queries that already aggregate (correlations) pass
        through. vmalert auto-prepends `_time:<group_interval>`, so the
        expression itself stays time-agnostic.
        """
        alert = _VMALERT_ALERT_NAME_RE.sub("_", rule.title).strip("_") or "Sigma_rule"
        expr = (
            query
            if "| stats " in query
            else f"{query} | stats count() as matches | filter matches:>0"
        )

        labels: dict[str, str] = {}
        if rule.level is not None:
            labels["severity"] = rule.level.name.lower()
        if rule.id is not None:
            labels["sigma_id"] = str(rule.id)

        annotations: dict[str, str] = {"summary": rule.title}
        if rule.description:
            annotations["description"] = rule.description
        if rule.author:
            annotations["author"] = rule.author
        if rule.tags:
            annotations["tags"] = ", ".join(str(t) for t in rule.tags)
        if rule.references:
            annotations["references"] = "\n".join(rule.references)

        return {
            "alert": alert,
            "expr": expr,
            "for": "0s",
            "labels": labels,
            "annotations": annotations,
        }

    def finalize_output_vmalert(self, queries: list[dict[str, Any]]) -> str:
        """Bundle vmalert rule dicts into a single rule-group YAML document.

        The group declares `type: vlogs` so vmalert routes the expressions
        through the VictoriaLogs `stats_query` API. `interval: 5m` matches the
        upstream docs example; tune via `-rule.evaluationInterval` or by
        editing the emitted YAML.
        """
        document = {
            "groups": [
                {
                    "name": "Sigma rules",
                    "type": "vlogs",
                    "interval": "5m",
                    "rules": list(queries),
                }
            ]
        }
        return yaml.safe_dump(document, sort_keys=False)

    # ----- grafana_alerting output format — see docs/mapping.md §15. -----
    # (Operational ceilings §16 documents the cross-format ceilings.)

    def _grafana_uid(self, rule: SigmaRule) -> str:
        """Derive a Grafana-valid alert rule UID from a Sigma rule.

        Grafana requires UIDs <= 40 chars, drawn from [A-Za-z0-9_-]. pySigma
        validates that ``rule.id`` is a UUID (36 chars, conforming charset),
        so it passes through unchanged. When ``id`` is absent, a stable
        14-char MD5 prefix of the title gives a deterministic UID.
        """
        if rule.id is not None:
            return str(rule.id)
        digest = hashlib.md5(rule.title.encode("utf-8")).hexdigest()
        return digest[:14]

    def finalize_query_grafana_alerting(
        self,
        rule: SigmaRule,
        query: str,
        _index: int,
        state: ConversionState,
    ) -> dict[str, Any]:
        """Render one Sigma rule as a Grafana provisioned alert rule.

        Emits a two-node ``data`` array: refId A is the VictoriaLogs
        ``stats_query`` (same `| stats count() as matches | filter matches:>0`
        wrap we use for vmalert, since alert evaluation hits the same stats
        endpoint), refId B is a threshold expression that fires when A returns
        a non-zero count. ``condition: B`` is the canonical Grafana pattern
        for "fire when the query returned matches".

        Defaults (``for: 0s``, ``noDataState: OK``, ``execErrState: OK``)
        suit detection rules: any match is enough to fire, and a query error
        or empty result is not itself an incident.
        """
        expr = (
            query
            if "| stats " in query
            else f"{query} | stats count() as matches | filter matches:>0"
        )

        labels: dict[str, str] = {}
        if rule.level is not None:
            level_name = rule.level.name.lower()
            labels["severity"] = _GRAFANA_SEVERITY_MAP.get(level_name, "info")
        if rule.id is not None:
            labels["sigma_id"] = str(rule.id)

        annotations: dict[str, str] = {"summary": rule.title}
        if rule.description:
            annotations["description"] = rule.description
        if rule.references:
            annotations["references"] = "\n".join(rule.references)

        ds_uid = self.grafana_datasource_uid
        data_query = {
            "refId": "A",
            "queryType": _VL_PLUGIN_QUERY_TYPE_STATS,
            "relativeTimeRange": {
                "from": self.grafana_relative_time_from,
                "to": 0,
            },
            "datasourceUid": ds_uid,
            "model": {
                "refId": "A",
                "datasource": {
                    "type": _VL_PLUGIN_DATASOURCE_TYPE,
                    "uid": ds_uid,
                },
                "expr": expr,
                "queryType": _VL_PLUGIN_QUERY_TYPE_STATS,
                "hide": False,
                "intervalMs": 1000,
                "maxDataPoints": 43200,
            },
        }
        threshold = {
            "refId": "B",
            "queryType": "",
            "relativeTimeRange": {"from": 0, "to": 0},
            "datasourceUid": _GRAFANA_EXPR_DS_UID,
            "model": {
                "refId": "B",
                "type": "threshold",
                "datasource": {
                    "type": _GRAFANA_EXPR_DS_UID,
                    "uid": _GRAFANA_EXPR_DS_UID,
                },
                "expression": "A",
                "conditions": [
                    {
                        "evaluator": {"type": "gt", "params": [0]},
                        "operator": {"type": "and"},
                        "query": {"params": ["B"]},
                        "reducer": {"type": "last", "params": []},
                        "type": "query",
                    }
                ],
                "hide": False,
                "intervalMs": 1000,
                "maxDataPoints": 43200,
            },
        }

        return {
            "uid": self._grafana_uid(rule),
            "title": rule.title,
            "condition": "B",
            "data": [data_query, threshold],
            "noDataState": "OK",
            "execErrState": "OK",
            "for": "0s",
            "isPaused": False,
            "annotations": annotations,
            "labels": labels,
        }

    def finalize_output_grafana_alerting(self, queries: list[dict[str, Any]]) -> str:
        """Wrap rule dicts in the ``apiVersion: 1`` provisioning envelope.

        Single group named ``sigma`` in folder ``sigma`` (both configurable).
        Drop the emitted file into ``/etc/grafana/provisioning/alerting/`` for
        Grafana to load on startup.
        """
        document = {
            "apiVersion": 1,
            "groups": [
                {
                    "orgId": self.grafana_org_id,
                    "name": "sigma",
                    "folder": self.grafana_folder,
                    "interval": self.grafana_interval,
                    "rules": list(queries),
                }
            ],
        }
        return yaml.safe_dump(document, sort_keys=False)
