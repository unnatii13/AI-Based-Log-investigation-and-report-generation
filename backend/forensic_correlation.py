import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple


FILE_RE = re.compile(r"(?P<file>[A-Za-z]:\\[^\s\"']+|/[^\s\"']+|[\w.-]+\.(?:docx?|xlsx?|pptx?|pdf|zip|7z|rar|txt|csv|db|enc|locked))", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_PATTERNS = (
    re.compile(r"\buser(?:name)?[=: ]+([A-Za-z0-9_.@-]+)", re.IGNORECASE),
    re.compile(r"\baccount(?: name)?[=: ]+([A-Za-z0-9_.@-]+)", re.IGNORECASE),
    re.compile(r"\bfor (?:invalid user )?([A-Za-z0-9_.@-]+)\b", re.IGNORECASE),
    re.compile(r"\bby user ([A-Za-z0-9_.@-]+)\b", re.IGNORECASE),
)
HOST_PATTERNS = (
    re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+([A-Za-z0-9_.-]+)\b"),
    re.compile(r"\bhost[=: ]+([A-Za-z0-9_.-]+)", re.IGNORECASE),
    re.compile(r"\bdevice[=: ]+([A-Za-z0-9_.-]+)", re.IGNORECASE),
)
USB_RE = re.compile(r"\b(?:usb|vid[_-]?[0-9a-f]{4}|pid[_-]?[0-9a-f]{4}|serial[=: ]+[A-Za-z0-9_.-]+|removable)\b", re.IGNORECASE)
PROCESS_RE = re.compile(r"\b([A-Za-z0-9_.-]+\.(?:exe|ps1|bat|cmd|dll|apk))\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:https?://)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:/[\w./?=&%+-]*)?", re.IGNORECASE)


class ForensicEntityExtractor:
    def extract(self, event: Dict) -> Dict:
        raw_log = event.get("raw_log", "")
        lowered = raw_log.lower()
        entities = {
            "users": self._matches(USER_PATTERNS, raw_log),
            "hosts": self._matches(HOST_PATTERNS, raw_log),
            "files": self._files(raw_log),
            "processes": sorted(set(PROCESS_RE.findall(raw_log))),
            "emails": sorted(set(EMAIL_RE.findall(raw_log))),
            "domains": self._domains(raw_log),
            "channels": self._channels(lowered),
            "usb_devices": self._usb_devices(raw_log),
            "apps": self._apps(raw_log, lowered),
            "ips": self._ips(raw_log, event.get("source_ip")),
        }
        return {key: value for key, value in entities.items() if value}

    def _matches(self, patterns: Iterable[re.Pattern], raw_log: str) -> List[str]:
        values = []
        for pattern in patterns:
            values.extend(match.group(1).strip(":,;") for match in pattern.finditer(raw_log))
        return sorted(set(value for value in values if value and value.lower() not in {"from", "user"}))

    def _files(self, raw_log: str) -> List[str]:
        files = []
        for match in FILE_RE.finditer(raw_log):
            value = match.group("file").rstrip(".,;)")
            if value.lower() in {"/all", "/quiet"}:
                continue
            if value.lower().endswith((".exe", ".dll", ".apk", ".ps1", ".bat", ".cmd")):
                continue
            files.append(value)
        return sorted(set(files))

    def _domains(self, raw_log: str) -> List[str]:
        domains = []
        for domain in DOMAIN_RE.findall(raw_log):
            if "." in domain and not domain.lower().endswith((".exe", ".dll", ".doc", ".docx", ".pdf", ".zip")):
                domains.append(domain.lower())
        return sorted(set(domains))

    def _channels(self, lowered: str) -> List[str]:
        channels = []
        terms = {
            "usb": ["usb", "removable", "mtp"],
            "bluetooth": ["bluetooth", "bt transfer", "obex"],
            "email": ["smtp", "email", "mail", "attachment"],
            "network": ["http", "https", "tcp", "udp", "dns", "ftp", "smb"],
            "android": ["android", "adb", "apk", "content://", "mtp"],
        }
        for channel, needles in terms.items():
            if any(needle in lowered for needle in needles):
                channels.append(channel)
        return channels

    def _usb_devices(self, raw_log: str) -> List[str]:
        if not USB_RE.search(raw_log):
            return []
        serial_match = re.search(r"\bserial[=: ]+([A-Za-z0-9_.-]+)", raw_log, re.IGNORECASE)
        vid_match = re.search(r"\bvid[_-]?([0-9a-f]{4})", raw_log, re.IGNORECASE)
        pid_match = re.search(r"\bpid[_-]?([0-9a-f]{4})", raw_log, re.IGNORECASE)
        parts = []
        if vid_match:
            parts.append(f"VID_{vid_match.group(1).upper()}")
        if pid_match:
            parts.append(f"PID_{pid_match.group(1).upper()}")
        if serial_match:
            parts.append(f"SERIAL_{serial_match.group(1)}")
        return [" ".join(parts) if parts else "USB/removable device"]

    def _apps(self, raw_log: str, lowered: str) -> List[str]:
        apps = sorted(set(PROCESS_RE.findall(raw_log)))
        android_match = re.findall(r"\b(?:package|app)[=: ]+([A-Za-z0-9_.-]+)", raw_log, flags=re.IGNORECASE)
        apps.extend(android_match)
        if "gmail" in lowered:
            apps.append("Gmail")
        if "whatsapp" in lowered:
            apps.append("WhatsApp")
        if "powershell" in lowered and "powershell.exe" not in [app.lower() for app in apps]:
            apps.append("powershell.exe")
        return sorted(set(apps))

    def _ips(self, raw_log: str, source_ip: Optional[str]) -> List[str]:
        ips = set(IP_RE.findall(raw_log))
        if source_ip and source_ip != "unknown":
            ips.add(source_ip)
        return sorted(ips)


class ForensicCorrelationEngine:
    TRANSFER_TERMS = ("copy", "copied", "transfer", "sent", "attachment", "mtp", "usb", "bluetooth", "email", "exfil")
    RANSOMWARE_TERMS = ("ransomware", "encrypt", "encrypted", ".locked", ".enc", "shadow copy", "vssadmin", "bcdedit")
    STOP_WORDS = {
        "a", "an", "and", "are", "as", "at", "be", "by", "case", "did", "do", "does", "event", "events",
        "for", "from", "give", "happen", "happened", "i", "in", "is", "it", "list", "log", "logs", "me",
        "of", "on", "or", "please", "show", "tell", "the", "this", "to", "was", "were", "with",
    }
    INTENT_RULES = {
        "file_transfer": {
            "terms": {"file", "left", "transfer", "transferred", "copy", "copied", "exfil", "exfiltration", "leak", "stolen"},
            "phases": {"File Access", "Device Transfer", "Outbound Transfer"},
            "channels": {"usb", "bluetooth", "email", "android"},
            "answer": "Likely file movement is shown by file access followed by device or outbound transfer evidence.",
        },
        "usb_transfer": {
            "terms": {"usb", "mtp", "removable", "phone", "android", "mobile", "device"},
            "phases": {"Device Transfer"},
            "channels": {"usb", "android"},
            "answer": "USB or mobile-device movement is shown by events containing USB, MTP, Android, or removable-device evidence.",
        },
        "bluetooth_transfer": {
            "terms": {"bluetooth", "obex"},
            "phases": {"Device Transfer"},
            "channels": {"bluetooth"},
            "answer": "Bluetooth movement is shown by events containing Bluetooth or OBEX transfer evidence.",
        },
        "email_transfer": {
            "terms": {"email", "mail", "gmail", "smtp", "attachment", "recipient", "receiver", "sent"},
            "phases": {"Outbound Transfer"},
            "channels": {"email"},
            "answer": "Email exfiltration evidence is shown by mail, SMTP, Gmail, or attachment events.",
        },
        "ransomware": {
            "terms": {"ransom", "ransomware", "infection", "infected", "malware", "encrypt", "encrypted", "encryption", "locked"},
            "phases": {"Initial Download", "Suspicious Execution", "Encryption Activity", "Persistence or Impact"},
            "raw_terms": {"ransomware", "encrypted", ".locked", ".enc", "ransom_note"},
            "answer": "The ransomware sequence starts with download or suspicious execution evidence and escalates into encryption or impact events.",
        },
        "initial_access": {
            "terms": {"first", "start", "started", "initial", "download", "appearance", "appeared", "entry", "payload"},
            "phases": {"Initial Download", "Suspicious Execution"},
            "raw_terms": {"download", "payload", "browser", "invoice_viewer"},
            "answer": "Initial compromise evidence is usually the earliest download, payload, or suspicious execution event.",
        },
        "encrypted_files": {
            "terms": {"encrypted", "locked", "affected", "files", "documents", "encrypted files", "which files"},
            "phases": {"Encryption Activity"},
            "raw_terms": {"encrypted", ".locked", ".enc"},
            "answer": "Encrypted or affected files are shown by encryption activity events.",
        },
        "process_activity": {
            "terms": {"process", "exe", "execution", "executed", "command", "powershell", "cmd", "vssadmin", "payload"},
            "phases": {"Suspicious Execution", "Persistence or Impact"},
            "answer": "Process evidence is shown by execution, PowerShell, command-line, and system utility events.",
        },
        "ip_evidence": {
            "terms": {"ip", "address", "source", "destination", "network", "c2", "command", "control", "beacon", "external"},
            "raw_terms": {"command and control", "beacon", "dst=", "destination"},
            "answer": "These events contain IP or network evidence useful for attribution and communication reconstruction.",
        },
        "user_evidence": {
            "terms": {"user", "account", "suspect", "employee", "analyst", "login", "logon"},
            "answer": "These events contain user or account evidence for attribution.",
        },
        "attack_events": {
            "terms": {"attack", "attacks", "suspicious", "alert", "critical", "high", "risk", "threat"},
            "verdicts": {"ATTACK", "SUSPICIOUS"},
            "answer": "These are the events classified as suspicious or attack-related.",
        },
        "timeline_summary": {
            "terms": {"timeline", "sequence", "chronology", "summary", "story", "reconstruct", "flow"},
            "answer": "This is the chronological incident sequence for the selected case.",
        },
    }

    def __init__(self, extractor: Optional[ForensicEntityExtractor] = None):
        self.extractor = extractor or ForensicEntityExtractor()

    def build_timeline(self, events: List[Dict]) -> Dict:
        enriched = [self._enrich(event) for event in events]
        enriched.sort(key=self._sort_key)
        scenario = self._infer_scenario(enriched)
        return {
            "scenario": scenario,
            "summary": self._summary(enriched, scenario),
            "timeline": [self._timeline_item(event, scenario) for event in enriched],
            "correlations": self._correlations(enriched),
            "entities": self._entity_summary(enriched),
        }

    def answer_query(self, events: List[Dict], query: str) -> Dict:
        timeline = self.build_timeline(events)
        items = timeline["timeline"]
        intent = self._detect_intent(query, timeline)
        selected = self._select_events_for_intent(items, intent)
        answer = self._compose_answer(intent, selected, timeline)

        if not selected:
            selected = items[:5]
            answer = "No direct match was found, so here are the earliest timeline events for context."

        return {
            "answer": answer,
            "intent": intent["name"],
            "confidence": intent["confidence"],
            "matched_entities": intent["entities"],
            "matched_count": len(selected),
            "events": selected[:20],
            "entities": timeline["entities"],
        }

    def _detect_intent(self, query: str, timeline: Dict) -> Dict:
        normalized = query.lower().strip()
        tokens = self._query_tokens(normalized)
        phrases = self._query_phrases(normalized)
        entity_hits = self._query_entity_hits(normalized, timeline.get("entities", {}))
        best_name = "timeline_summary"
        best_score = 0

        for name, rule in self.INTENT_RULES.items():
            terms = rule.get("terms", set())
            score = sum(3 for term in terms if term in tokens or term in phrases or term in normalized)
            score += sum(2 for raw_term in rule.get("raw_terms", set()) if raw_term in normalized)

            if name == "file_transfer" and any(entity["type"] == "files" for entity in entity_hits):
                score += 3
            if name == "user_evidence" and any(entity["type"] == "users" for entity in entity_hits):
                score += 4
            if name == "ip_evidence" and any(entity["type"] == "ips" for entity in entity_hits):
                score += 4
            if name in {"process_activity", "ransomware"} and any(entity["type"] in {"processes", "apps"} for entity in entity_hits):
                score += 3

            if score > best_score:
                best_name = name
                best_score = score

        if any(word in tokens for word in {"who", "suspect", "account", "user"}):
            best_name = "user_evidence"
        if any(word in tokens for word in {"when", "first", "start", "started"}):
            if best_name in {"ransomware", "process_activity", "timeline_summary"}:
                best_name = "initial_access"
        if any(word in tokens for word in {"where", "ip", "network", "external"}):
            best_name = "ip_evidence" if best_score < 8 else best_name
        if {"encrypted", "files"}.issubset(set(tokens)) or "encrypted files" in phrases or "which files" in phrases:
            best_name = "encrypted_files"

        return {
            "name": best_name,
            "tokens": tokens,
            "entities": entity_hits,
            "confidence": min(100, 35 + best_score * 8 + len(entity_hits) * 5),
        }

    def _query_tokens(self, normalized: str) -> List[str]:
        tokens = re.findall(r"[a-z0-9_.@:-]+", normalized)
        expanded = []
        synonyms = {
            "stolen": "exfil",
            "leaked": "exfil",
            "leak": "exfil",
            "outside": "external",
            "attacker": "attack",
            "phone": "android",
            "mobile": "android",
            "started": "start",
            "begin": "start",
            "began": "start",
            "locked": "encrypted",
            "encrypting": "encrypted",
        }
        for token in tokens:
            if token not in self.STOP_WORDS:
                expanded.append(token)
            synonym = synonyms.get(token)
            if synonym:
                expanded.append(synonym)
        return sorted(set(expanded))

    def _query_phrases(self, normalized: str) -> List[str]:
        phrases = []
        phrase_map = {
            "left the system": "exfil",
            "leave the system": "exfil",
            "sent outside": "external",
            "command and control": "c2",
            "c and c": "c2",
            "source ip": "source ip",
            "destination ip": "destination ip",
            "affected files": "affected files",
            "encrypted files": "encrypted files",
            "which files": "which files",
        }
        for phrase, replacement in phrase_map.items():
            if phrase in normalized:
                phrases.append(replacement)
        return phrases

    def _query_entity_hits(self, normalized: str, entities: Dict) -> List[Dict]:
        hits = []
        for entity_type, values in entities.items():
            for value in values:
                value_text = str(value).lower()
                basename = value_text.split("\\")[-1].split("/")[-1]
                if value_text and (value_text in normalized or basename in normalized):
                    hits.append({"type": entity_type, "value": value})
        return hits

    def _select_events_for_intent(self, items: List[Dict], intent: Dict) -> List[Dict]:
        rule = self.INTENT_RULES.get(intent["name"], self.INTENT_RULES["timeline_summary"])
        scored = []
        for index, item in enumerate(items):
            score = self._event_relevance(item, rule, intent)
            if score:
                scored.append((score, index, item))

        if not scored and intent["name"] == "timeline_summary":
            return items[:12]

        scored.sort(key=lambda value: (-value[0], value[1]))
        selected = [item for _, _, item in scored]
        if intent["name"] in {"initial_access"} and selected:
            return selected[:5]
        return selected

    def _event_relevance(self, item: Dict, rule: Dict, intent: Dict) -> int:
        raw = item.get("raw_log", "").lower()
        score = 0

        if item.get("phase") in rule.get("phases", set()):
            score += 8
        if item.get("verdict") in rule.get("verdicts", set()):
            score += 6
        if rule.get("channels") and any(channel in rule["channels"] for channel in item.get("channels", [])):
            score += 7
        if intent["name"] == "ip_evidence" and item.get("source_ip") != "unknown":
            score += 8

        for term in rule.get("terms", set()):
            if self._contains_term(raw, term):
                score += 2
        for term in rule.get("raw_terms", set()):
            if term in raw:
                score += 4
        for token in intent.get("tokens", []):
            if len(token) > 2 and token in raw:
                score += 1
        for entity in intent.get("entities", []):
            entity_value = str(entity["value"]).lower()
            basename = entity_value.split("\\")[-1].split("/")[-1]
            if entity_value in raw or basename in raw:
                score += 10

        return score

    def _contains_term(self, text: str, term: str) -> bool:
        if " " in term:
            return term in text
        return re.search(rf"\b{re.escape(term)}\b", text) is not None

    def _compose_answer(self, intent: Dict, selected: List[Dict], timeline: Dict) -> str:
        rule = self.INTENT_RULES.get(intent["name"], self.INTENT_RULES["timeline_summary"])
        if not selected:
            return rule["answer"]

        if intent["name"] == "encrypted_files":
            files = self._unique_from_items(selected, "files")
            return f"{rule['answer']} Files found: {', '.join(files[:8]) if files else 'none extracted'}."
        if intent["name"] == "user_evidence":
            users = self._unique_from_items(selected, "users")
            return f"{rule['answer']} Users found: {', '.join(users[:8]) if users else 'none extracted'}."
        if intent["name"] == "ip_evidence":
            ips = sorted(
                {
                    ip
                    for item in selected
                    for ip in (([item["source_ip"]] if item.get("source_ip") != "unknown" else []) + item.get("ips", []))
                }
            )
            return f"{rule['answer']} IPs found: {', '.join(ips[:10]) if ips else 'none extracted'}."
        if intent["name"] == "process_activity":
            processes = self._unique_from_items(selected, "processes") or self._unique_from_items(selected, "apps")
            return f"{rule['answer']} Processes/apps found: {', '.join(processes[:8]) if processes else 'review matching events'}."
        if intent["name"] == "initial_access":
            first = selected[0]
            return f"{rule['answer']} Earliest matching event: {first['time']} - {first['phase']}."
        if intent["name"] == "timeline_summary":
            return timeline.get("summary") or rule["answer"]

        phases = []
        for item in selected:
            if item["phase"] not in phases:
                phases.append(item["phase"])
        return f"{rule['answer']} Matching phases: {', '.join(phases[:6])}."

    def _unique_from_items(self, items: List[Dict], key: str) -> List[str]:
        values = []
        for item in items:
            for value in item.get(key, []):
                if value not in values:
                    values.append(value)
        return values

    def _enrich(self, event: Dict) -> Dict:
        enriched = dict(event)
        enriched["entities"] = self.extractor.extract(event)
        enriched["phase"] = self._phase(enriched)
        enriched["confidence"] = self._confidence(enriched)
        return enriched

    def _phase(self, event: Dict) -> str:
        raw = event.get("raw_log", "").lower()
        event_type = event.get("event_type", "")
        channels = set(event.get("entities", {}).get("channels", []))

        if "usb" in channels or "bluetooth" in channels:
            return "Device Transfer"
        if "email" in channels or any(term in raw for term in ("smtp", "attachment", "sent mail")):
            return "Outbound Transfer"
        if any(term in raw for term in ("downloaded", "browser", "http get", "payload")):
            return "Initial Download"
        if any(term in raw for term in ("powershell", "cmd.exe", "process created", "encodedcommand", "wscript", "rundll32")):
            return "Suspicious Execution"
        if any(term in raw for term in ("shadow copy", "vssadmin", "bcdedit", "delete backup")):
            return "Persistence or Impact"
        if any(term in raw for term in self.RANSOMWARE_TERMS):
            return "Encryption Activity"
        if event.get("entities", {}).get("files") and any(term in raw for term in ("open", "read", "access", "copy")):
            return "File Access"
        if "auth" in event_type or "logon" in event_type or "login" in raw:
            return "Access Event"
        if event.get("verdict") == "ATTACK":
            return "Attack Indicator"
        if event.get("verdict") == "SUSPICIOUS":
            return "Suspicious Indicator"
        return "Context Event"

    def _confidence(self, event: Dict) -> int:
        score = int(min(max(float(event.get("risk_score", 0)), 0), 100))
        entity_bonus = min(sum(len(values) for values in event.get("entities", {}).values()) * 3, 20)
        verdict_bonus = 15 if event.get("verdict") == "ATTACK" else 8 if event.get("verdict") == "SUSPICIOUS" else 0
        return min(100, score + entity_bonus + verdict_bonus)

    def _infer_scenario(self, events: List[Dict]) -> str:
        text = "\n".join(event.get("raw_log", "").lower() for event in events)
        transfer_score = sum(text.count(term) for term in self.TRANSFER_TERMS)
        ransomware_score = sum(text.count(term) for term in self.RANSOMWARE_TERMS)
        if ransomware_score > transfer_score and ransomware_score:
            return "Ransomware Infection Timeline"
        if transfer_score:
            return "Cross-Device File Transfer Timeline"
        return "General Forensic Timeline"

    def _summary(self, events: List[Dict], scenario: str) -> str:
        if not events:
            return "No events are available for correlation."
        attacks = sum(1 for event in events if event.get("verdict") == "ATTACK")
        suspicious = sum(1 for event in events if event.get("verdict") == "SUSPICIOUS")
        first = self._event_time_label(events[0])
        last = self._event_time_label(events[-1])
        return f"{scenario}: {len(events)} events from {first} to {last}, including {attacks} attacks and {suspicious} suspicious events."

    def _timeline_item(self, event: Dict, scenario: str) -> Dict:
        entities = event.get("entities", {})
        return {
            "id": event.get("id"),
            "line_no": event.get("line_no"),
            "time": self._event_time_label(event),
            "source_ip": event.get("source_ip") or "unknown",
            "severity": event.get("severity") or "INFO",
            "event_type": event.get("event_type") or "general",
            "verdict": event.get("verdict") or "NORMAL",
            "risk_score": event.get("risk_score") or 0,
            "phase": event.get("phase") or "Context Event",
            "confidence": event.get("confidence") or 0,
            "explanation": event.get("explanation") or "",
            "raw_log": event.get("raw_log") or "",
            "files": entities.get("files", []),
            "users": entities.get("users", []),
            "hosts": entities.get("hosts", []),
            "processes": entities.get("processes", []),
            "emails": entities.get("emails", []),
            "domains": entities.get("domains", []),
            "channels": entities.get("channels", []),
            "apps": entities.get("apps", []),
            "ips": entities.get("ips", []),
            "scenario": scenario,
        }

    def _correlations(self, events: List[Dict]) -> List[Dict]:
        links = []
        file_events = defaultdict(list)
        ip_events = defaultdict(list)
        user_events = defaultdict(list)

        for event in events:
            entities = event.get("entities", {})
            for file_name in entities.get("files", []):
                file_events[file_name].append(event)
            for ip in entities.get("ips", []):
                ip_events[ip].append(event)
            for user in entities.get("users", []):
                user_events[user].append(event)

        links.extend(self._links_from_groups(file_events, "file", "Same file appears across multiple forensic events."))
        links.extend(self._links_from_groups(ip_events, "ip", "Same IP address appears across multiple forensic events."))
        links.extend(self._links_from_groups(user_events, "user", "Same user appears across multiple forensic events."))
        return links[:30]

    def _links_from_groups(self, grouped: Dict[str, List[Dict]], entity_type: str, reason: str) -> List[Dict]:
        links = []
        for value, related in grouped.items():
            if len(related) < 2:
                continue
            phases = [event.get("phase", "Context Event") for event in related]
            links.append(
                {
                    "entity_type": entity_type,
                    "entity": value,
                    "event_ids": [event.get("id") for event in related if event.get("id") is not None],
                    "phases": phases,
                    "reason": reason,
                }
            )
        return links

    def _entity_summary(self, events: List[Dict]) -> Dict:
        counters = {
            "users": Counter(),
            "hosts": Counter(),
            "files": Counter(),
            "processes": Counter(),
            "emails": Counter(),
            "domains": Counter(),
            "channels": Counter(),
            "apps": Counter(),
            "ips": Counter(),
        }
        for event in events:
            for key, values in event.get("entities", {}).items():
                if key in counters:
                    counters[key].update(values)
        return {key: dict(counter.most_common(12)) for key, counter in counters.items() if counter}

    def _sort_key(self, event: Dict) -> Tuple[int, str, int]:
        value = event.get("event_time") or event.get("timestamp") or ""
        parsed = self._parse_time(value)
        if parsed:
            return (0, parsed.isoformat(), int(event.get("id") or event.get("line_no") or 0))
        return (1, value, int(event.get("id") or event.get("line_no") or 0))

    def _parse_time(self, value: str) -> Optional[datetime]:
        if not value:
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

    def _event_time_label(self, event: Dict) -> str:
        return event.get("event_time") or event.get("timestamp") or event.get("ingested_at") or "unknown"
