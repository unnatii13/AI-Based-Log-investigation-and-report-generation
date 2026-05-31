import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from .forensic_correlation import ForensicCorrelationEngine


class LogMindAssistant:
    """Evidence-first analyst assistant over already analyzed case events."""

    MITRE_RULES = (
        ("T1110", "Brute Force", ("failed password", "failed login", "4625", "invalid user", "authentication failure")),
        ("T1078", "Valid Accounts", ("accepted password", "successful login", "successful logon", "4624", "logon successful")),
        ("T1059", "Command and Scripting Interpreter", ("powershell", "cmd.exe", "encodedcommand", "bash", "script")),
        ("T1105", "Ingress Tool Transfer", ("downloaded", "wget", "curl", "http get", "payload")),
        ("T1021", "Remote Services", ("ssh", "rdp", "remote login")),
        ("T1041", "Exfiltration Over C2 Channel", ("exfil", "smtp", "attachment", "mail upload", "sent email")),
        ("T1091", "Replication Through Removable Media", ("usb", "mtp", "removable", "android device")),
        ("T1486", "Data Encrypted for Impact", ("ransomware", "encrypted", ".locked", ".enc")),
        ("T1490", "Inhibit System Recovery", ("vssadmin", "shadow copy", "delete shadows", "bcdedit")),
        ("T1136", "Create Account", ("new user", "user created", "4720")),
        ("T1068", "Exploitation for Privilege Escalation", ("privilege escalation", "4672", "sudo", "elevated privilege")),
    )

    STOP_WORDS = {
        "a", "about", "all", "an", "and", "are", "case", "did", "do", "for", "from", "give", "happen",
        "happened", "in", "is", "it", "last", "log", "logs", "me", "of", "on", "or", "show", "tell",
        "the", "this", "to", "was", "were", "what", "when", "where", "why", "with",
    }

    def __init__(self, correlation_engine: ForensicCorrelationEngine = None):
        self.correlation_engine = correlation_engine or ForensicCorrelationEngine()

    def answer(self, events: List[Dict], query: str) -> Dict:
        timeline = self.correlation_engine.build_timeline(events)
        items = timeline.get("timeline", [])
        if not items:
            return {
                "answer": "No analyzed logs are available for this case yet. Ingest logs before asking LogMind to investigate them.",
                "intent": "empty_case",
                "confidence": 100,
                "matched_entities": [],
                "matched_count": 0,
                "events": [],
                "entities": {},
            }

        intent = self._detect_intent(query)

        handlers = {
            "count_events": self._count_events,
            "failed_logins": self._failed_logins,
            "host_timeline": self._host_timeline,
            "mitre_mapping": self._mitre_mapping,
            "alert_explanation": self._alert_explanation,
            "incident_summary": self._incident_summary,
            "next_steps": self._next_steps,
            "incident_report": self._incident_report,
            "suspicious_ips": self._suspicious_ips,
            "attack_events": self._attack_events,
            "encrypted_files": self._encrypted_files,
            "file_transfer": self._file_transfer,
            "ransomware_start": self._ransomware_start,
        }
        result = handlers.get(intent, self._general_search)(items, timeline, query)

        result.setdefault("intent", intent)
        result.setdefault("confidence", self._confidence(intent, result.get("matched_count", 0), len(items)))
        result.setdefault("matched_entities", [])
        result.setdefault("entities", timeline.get("entities", {}))
        result["events"] = result.get("events", [])[:20]
        return result

    def _detect_intent(self, query: str) -> str:
        text = query.lower()
        if any(term in text for term in ("mitre", "att&ck", "attack mapping", "tactic", "technique")):
            return "mitre_mapping"
        if any(term in text for term in ("how many", "how much", "count ", "number of", "total ")):
            return "count_events"
        if any(term in text for term in ("failed login", "failed logon", "failed password", "4625", "brute force")):
            return "failed_logins"
        if any(term in text for term in ("what happened on this host", "what happened on host", "host timeline", "what happened on ")):
            return "host_timeline"
        if any(term in text for term in ("why was this alert", "why alert", "why was it flagged", "why suspicious")):
            return "alert_explanation"
        if any(term in text for term in ("summarize", "summary", "incident overview", "what happened")):
            return "incident_summary"
        if any(term in text for term in ("investigate next", "next step", "recommend", "what should i investigate")):
            return "next_steps"
        if any(term in text for term in ("report", "incident report", "case report")):
            return "incident_report"
        if any(term in text for term in ("suspicious ip", "attacker ip", "source ip", "external ip", "c2")):
            return "suspicious_ips"
        if any(term in text for term in ("attack event", "suspicious event", "alert event", "threat event")):
            return "attack_events"
        if any(term in text for term in ("encrypted files", "affected files", "which files", "locked files")):
            return "encrypted_files"
        if any(term in text for term in ("file leave", "left the system", "exfil", "transfer", "stolen", "sent outside")):
            return "file_transfer"
        if any(term in text for term in ("ransomware start", "ransomware began", "infection start", "infection began")):
            return "ransomware_start"
        return "general_search"

    def _count_events(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        selected = self._matching_events(items, query)
        if not selected:
            selected = self._time_filtered(items, query)
        label = self._topic_label(query)
        answer = f"{len(selected)} {label} event(s) were found."
        if selected:
            source_counts = Counter(ip for item in selected for ip in self._ips(item))
            user_counts = Counter(user for item in selected for user in item.get("users", []))
            details = []
            if source_counts:
                details.append(f"top IP {self._top_label(source_counts)}")
            if user_counts:
                details.append(f"top account {self._top_label(user_counts)}")
            if details:
                answer += " " + "; ".join(details) + "."
        return {"answer": answer, "matched_count": len(selected), "events": selected}

    def _failed_logins(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        selected = [
            item for item in self._time_filtered(items, query)
            if self._has_any(item, ("failed password", "failed login", "failed logon", "4625", "invalid user"))
            or "failed_log" in item.get("event_type", "")
        ]
        source_counts = Counter(item.get("source_ip") for item in selected if item.get("source_ip") != "unknown")
        user_counts = Counter(user for item in selected for user in item.get("users", []))
        answer = (
            f"{len(selected)} failed login event(s) found. "
            f"Top source IP: {self._top_label(source_counts)}. "
            f"Most targeted account: {self._top_label(user_counts)}."
        )
        return {"answer": answer, "matched_count": len(selected), "events": selected}

    def _host_timeline(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        host = self._extract_named_value(query, ("host", "device")) or self._entity_in_query(query, timeline.get("entities", {}).get("hosts", {}))
        selected = items
        if host:
            selected = [
                item for item in items
                if host.lower() in item.get("raw_log", "").lower()
                or host.lower() in [value.lower() for value in item.get("hosts", [])]
            ]
        answer = self._timeline_answer(selected, f"Chronological activity{f' for {host}' if host else ''}")
        return {"answer": answer, "matched_count": len(selected), "events": selected[:30]}

    def _mitre_mapping(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        mapped = []
        for item in items:
            raw = " ".join(
                str(item.get(key, "")).lower()
                for key in ("raw_log", "event_type", "phase", "explanation")
            )
            for technique_id, name, terms in self.MITRE_RULES:
                if any(term in raw for term in terms):
                    mapped.append((technique_id, name, item))

        by_technique = defaultdict(list)
        for technique_id, name, item in mapped:
            by_technique[(technique_id, name)].append(item)

        if not by_technique:
            return {
                "answer": "No ATT&CK technique mapping was found from the current analyzed evidence.",
                "matched_count": 0,
                "events": [],
            }

        parts = [
            f"{technique_id} - {name} ({len(events)} event{'s' if len(events) != 1 else ''})"
            for (technique_id, name), events in sorted(by_technique.items())
        ]
        evidence = [events[0] for events in by_technique.values()]
        return {
            "answer": "MITRE ATT&CK mapping: " + "; ".join(parts) + ".",
            "matched_count": len(mapped),
            "events": evidence,
            "mitre": [
                {"technique_id": technique_id, "name": name, "event_count": len(events)}
                for (technique_id, name), events in sorted(by_technique.items())
            ],
        }

    def _alert_explanation(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        selected = self._matching_events(items, query) or self._risk_events(items)
        reasons = Counter()
        for item in selected:
            for reason in self._reasons(item):
                reasons[reason] += 1
        evidence_ids = self._event_ids(selected)
        answer = (
            "Suspicious activity was flagged because "
            + ", ".join(f"{reason} ({count})" for reason, count in reasons.most_common(5))
            + (f". Evidence: {', '.join(evidence_ids[:8])}." if evidence_ids else ".")
            if reasons
            else "No high-risk alert evidence was found in the selected case."
        )
        return {"answer": answer, "matched_count": len(selected), "events": selected}

    def _incident_summary(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        risk_events = self._risk_events(items)
        phase_counts = Counter(item.get("phase") for item in items)
        verdict_counts = Counter(item.get("verdict") for item in items)
        answer = (
            f"{timeline.get('summary')} "
            f"Top phases: {self._counter_list(phase_counts)}. "
            f"Verdicts: {self._counter_list(verdict_counts)}."
        )
        return {"answer": answer, "matched_count": len(risk_events or items), "events": (risk_events or items)}

    def _next_steps(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        risk_events = self._risk_events(items)
        ips = Counter(ip for item in risk_events for ip in self._ips(item))
        users = Counter(user for item in risk_events for user in item.get("users", []))
        files = Counter(file_name for item in risk_events for file_name in item.get("files", []))
        steps = [
            f"Validate the highest-risk events first ({len(risk_events)} suspicious/attack events).",
            f"Pivot on top IP {self._top_label(ips)}.",
            f"Review account activity for {self._top_label(users)}.",
            f"Preserve and inspect file evidence {self._top_label(files)}.",
            "Export the case report and verify the chain of custody before sharing evidence.",
        ]
        return {"answer": "Recommended next steps: " + " ".join(steps), "matched_count": len(risk_events), "events": risk_events}

    def _incident_report(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        risk_events = self._risk_events(items)
        mitre = self._mitre_mapping(items, timeline, query).get("mitre", [])
        techniques = ", ".join(f"{item['technique_id']} {item['name']}" for item in mitre[:6]) or "none mapped"
        answer = (
            f"Incident report draft: {timeline.get('summary')} "
            f"Key evidence includes {len(risk_events)} suspicious/attack events, "
            f"{len(timeline.get('entities', {}).get('ips', {}))} IP indicators, "
            f"and {len(timeline.get('entities', {}).get('files', {}))} file indicators. "
            f"ATT&CK techniques: {techniques}. "
            f"Recommended conclusion: preserve evidence, validate affected users/hosts, and export the formal report."
        )
        return {"answer": answer, "matched_count": len(risk_events or items), "events": (risk_events or items)}

    def _suspicious_ips(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        selected = [
            item for item in items
            if item.get("verdict") in {"ATTACK", "SUSPICIOUS"}
            or self._has_any(item, ("block", "denied", "command and control", "beacon", "failed", "malware", "ransomware"))
        ]
        ip_counts = Counter(ip for item in selected for ip in self._ips(item))
        answer = (
            "Suspicious IP evidence: "
            + (", ".join(f"{ip} ({count})" for ip, count in ip_counts.most_common(10)) if ip_counts else "none found")
            + "."
        )
        return {"answer": answer, "matched_count": len(selected), "events": selected}

    def _attack_events(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        selected = self._risk_events(items)
        answer = f"{len(selected)} suspicious or attack-related event(s) found."
        return {"answer": answer, "matched_count": len(selected), "events": selected}

    def _encrypted_files(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        selected = [item for item in items if item.get("phase") == "Encryption Activity" or self._has_any(item, ("encrypted", ".locked", ".enc"))]
        files = []
        for item in selected:
            for file_name in item.get("files", []):
                if file_name not in files:
                    files.append(file_name)
        answer = f"Encrypted or affected files: {', '.join(files[:12]) if files else 'none extracted'}."
        return {"answer": answer, "matched_count": len(selected), "events": selected}

    def _file_transfer(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        transfer_channels = {"usb", "bluetooth", "email", "android"}
        transfer_terms = ("copied", "transfer", "sent email", "attachment", "mtp", "obex", "mail upload", "exfil")
        selected = [
            item for item in items
            if item.get("phase") in {"Device Transfer", "Outbound Transfer"}
            or transfer_channels.intersection(item.get("channels", []))
            or self._has_any(item, transfer_terms)
        ]
        channels = Counter(channel for item in selected for channel in item.get("channels", []))
        files = Counter(file_name for item in selected for file_name in item.get("files", []))
        answer = (
            f"File movement evidence was found across {len(selected)} event(s). "
            f"Channels: {self._counter_list(channels) or 'none extracted'}. "
            f"Key files: {self._counter_list(files, limit=5) or 'none extracted'}."
        )
        return {"answer": answer, "matched_count": len(selected), "events": selected}

    def _ransomware_start(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        selected = [
            item for item in items
            if item.get("phase") in {"Initial Download", "Suspicious Execution", "Encryption Activity"}
            or self._has_any(item, ("ransomware", "payload", "downloaded", "encodedcommand", "encrypted"))
        ]
        first = selected[0] if selected else None
        answer = (
            f"Ransomware-related activity appears to start at {first.get('time')} with {first.get('phase')}."
            if first
            else "No ransomware start evidence was found in this case."
        )
        return {"answer": answer, "matched_count": len(selected), "events": selected[:10]}

    def _general_search(self, items: List[Dict], timeline: Dict, query: str) -> Dict:
        selected = self._matching_events(items, query)
        if selected:
            return {
                "answer": f"Found {len(selected)} event(s) related to your question. Showing the strongest evidence first.",
                "matched_count": len(selected),
                "events": selected,
            }
        return {
            "answer": "I could not find evidence matching that question in the analyzed logs. Try asking about failed logins, suspicious IPs, attack events, MITRE mapping, timeline, ransomware, or file transfer.",
            "matched_count": 0,
            "events": [],
        }

    def _risk_events(self, items: List[Dict]) -> List[Dict]:
        return [
            item for item in items
            if item.get("verdict") in {"ATTACK", "SUSPICIOUS"}
            or item.get("severity") in {"CRITICAL", "ALERT"}
        ]

    def _matching_events(self, items: List[Dict], query: str) -> List[Dict]:
        tokens = self._tokens(query)
        if not tokens:
            return []

        selected_items = self._time_filtered(items, query)
        scored: List[Tuple[int, int, Dict]] = []
        for index, item in enumerate(selected_items):
            searchable = " ".join(
                str(value).lower()
                for key in ("raw_log", "phase", "source_ip", "severity", "event_type", "verdict", "explanation")
                for value in [item.get(key, "")]
            )
            searchable += " " + " ".join(
                str(value).lower()
                for key in ("users", "hosts", "files", "processes", "emails", "domains", "channels", "apps", "ips")
                for value in item.get(key, [])
            )
            score = sum(2 for token in tokens if token in searchable)
            if item.get("verdict") in {"ATTACK", "SUSPICIOUS"}:
                score += 1
            if score:
                scored.append((score, index, item))

        scored.sort(key=lambda value: (-value[0], value[1]))
        return [item for _, _, item in scored]

    def _has_any(self, item: Dict, terms: Tuple[str, ...]) -> bool:
        raw = item.get("raw_log", "").lower()
        return any(term in raw for term in terms)

    def _ips(self, item: Dict) -> List[str]:
        values = []
        if item.get("source_ip") and item.get("source_ip") != "unknown":
            values.append(item["source_ip"])
        values.extend(item.get("ips", []))
        return sorted(set(values))

    def _reasons(self, item: Dict) -> List[str]:
        reasons = []
        raw = item.get("raw_log", "").lower()
        if item.get("severity") in {"CRITICAL", "ALERT", "ERROR", "WARNING"}:
            reasons.append(f"severity {item.get('severity')}")
        if item.get("verdict") in {"ATTACK", "SUSPICIOUS"}:
            reasons.append(f"verdict {item.get('verdict')}")
        if any(term in raw for term in ("failed", "invalid user", "4625")):
            reasons.append("failed authentication")
        if any(term in raw for term in ("powershell", "encodedcommand", "cmd.exe")):
            reasons.append("suspicious command execution")
        if any(term in raw for term in ("ransomware", "encrypted", ".locked")):
            reasons.append("ransomware or encryption evidence")
        if any(term in raw for term in ("usb", "mtp", "attachment", "smtp", "bluetooth")):
            reasons.append("file movement evidence")
        return reasons or ["supporting evidence"]

    def _tokens(self, query: str) -> List[str]:
        synonyms = {
            "blocked": "block",
            "denied": "deny",
            "logons": "login",
            "logins": "login",
            "attacker": "attack",
            "techniques": "technique",
            "mapped": "mapping",
        }
        tokens = []
        for token in re.findall(r"[a-z0-9_.@:-]+", query.lower()):
            if len(token) <= 2 or token in self.STOP_WORDS:
                continue
            tokens.append(token)
            if token in synonyms:
                tokens.append(synonyms[token])
        return [
            token for index, token in enumerate(tokens)
            if token not in tokens[:index]
        ]

    def _extract_named_value(self, query: str, labels: Tuple[str, ...]) -> str:
        for label in labels:
            match = re.search(rf"\b{label}\s*[=: ]\s*([A-Za-z0-9_.-]+)", query, flags=re.IGNORECASE)
            if match:
                return match.group(1)
        return ""

    def _entity_in_query(self, query: str, entity_counts: Dict) -> str:
        normalized = query.lower()
        for value in entity_counts:
            if str(value).lower() in normalized:
                return str(value)
        return ""

    def _time_filtered(self, items: List[Dict], query: str) -> List[Dict]:
        window = self._time_window(query)
        if not window:
            return items

        parsed = [(self._parse_item_time(item), item) for item in items]
        dated = [(value, item) for value, item in parsed if value]
        if not dated:
            return items

        latest = max(value for value, _ in dated)
        cutoff = latest - window
        filtered = [item for value, item in dated if value >= cutoff]
        return filtered or items

    def _time_window(self, query: str) -> timedelta:
        match = re.search(r"\blast\s+(\d+)\s*(hour|hours|hr|hrs|day|days)\b", query, flags=re.IGNORECASE)
        if not match:
            return None
        amount = int(match.group(1))
        unit = match.group(2).lower()
        if unit.startswith(("hour", "hr")):
            return timedelta(hours=amount)
        return timedelta(days=amount)

    def _parse_item_time(self, item: Dict):
        value = item.get("time")
        if not value or value == "unknown":
            return None
        normalized = value.replace("Z", "").replace("T", " ")
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%d/%b/%Y:%H:%M:%S"):
            try:
                return datetime.strptime(normalized[:26], fmt)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(normalized)
        except ValueError:
            return None

    def _topic_label(self, query: str) -> str:
        text = query.lower()
        if "firewall" in text or "blocked" in text or "denied" in text:
            return "firewall/block"
        if "failed" in text or "login" in text or "logon" in text:
            return "authentication"
        if "attack" in text or "suspicious" in text or "alert" in text:
            return "suspicious"
        if "file" in text or "transfer" in text or "exfil" in text:
            return "file movement"
        return "matching"

    def _event_ids(self, items: List[Dict]) -> List[str]:
        values = []
        for item in items:
            raw = item.get("raw_log", "")
            for match in re.finditer(r"\b(?:EventID|event_id|event id|id)[=: ]+(\d{3,5})\b", raw, re.IGNORECASE):
                label = f"Event ID {match.group(1)}"
                if label not in values:
                    values.append(label)
        return values

    def _timeline_answer(self, selected: List[Dict], title: str) -> str:
        if not selected:
            return f"{title}: no matching events found."
        points = [f"{item.get('time')} {item.get('phase')}" for item in selected[:8]]
        return f"{title}: " + " -> ".join(points) + "."

    def _top_label(self, counter: Counter) -> str:
        if not counter:
            return "none found"
        value, count = counter.most_common(1)[0]
        return f"{value} ({count})"

    def _counter_list(self, counter: Counter, limit: int = 6) -> str:
        return ", ".join(f"{key} ({count})" for key, count in counter.most_common(limit))

    def _confidence(self, intent: str, matched_count: int, total_count: int) -> int:
        if matched_count == 0:
            return 25
        base = 70 if intent != "general_search" else 55
        coverage = min(20, int((matched_count / max(total_count, 1)) * 20))
        return min(95, base + coverage)
