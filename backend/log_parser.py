import ipaddress
import json
import re
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional, Type

from .domain import ParsedLog


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ISO_TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b")
APACHE_TIME_RE = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})")
SYSLOG_TIME_RE = re.compile(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")
WINDOWS_EVENT_ID_RE = re.compile(r"\b(?:event(?:\s+id)?|eventid|id)[:= ]+(\d{3,5})\b", re.IGNORECASE)

SEVERITY_WORDS = {
    "critical": "CRITICAL",
    "crit": "CRITICAL",
    "fatal": "CRITICAL",
    "error": "ERROR",
    "err": "ERROR",
    "warning": "WARNING",
    "warn": "WARNING",
    "alert": "ALERT",
    "block": "WARNING",
    "blocked": "WARNING",
    "notice": "NOTICE",
    "info": "INFO",
    "debug": "DEBUG",
}

EVENT_KEYWORDS = {
    "web_attack": ["sqlmap", "union select", "' or '1'='1", "login.php", "wp-login", "xss", "csrf"],
    "authentication": ["login", "logon", "auth", "password", "credential", "ssh", "rdp"],
    "file_activity": ["file", "delete", "deleted", "modify", "chmod", "write", "opened", "copied"],
    "file_transfer": ["mtptransfer", "obex transfer", "sent email", "attachment", "mail upload", "channel=usb", "channel=bluetooth"],
    "network": ["connection", "connect", "firewall", "port", "dns", "http", "tcp", "udp"],
    "malware": ["malware", "virus", "trojan", "ransomware", "payload"],
    "privilege": ["sudo", "admin", "root", "privilege", "elevat"],
    "process": ["process", "cmd", "powershell", "bash", "script", "exec"],
    "usb": ["usb", "removable"],
}

SUSPICIOUS_TERMS = [
    "failed",
    "failure",
    "denied",
    "unauthorized",
    "bruteforce",
    "brute force",
    "exploit",
    "injection",
    "malware",
    "ransomware",
    "powershell",
    "encodedcommand",
    "cmd.exe",
    "wget",
    "curl",
    "sqlmap",
    "union select",
    "' or '1'='1",
    "invalid user",
    "ufw block",
    "delete",
    "deleted",
    "sudo",
    "mtptransfer",
    "obex transfer",
    "sent email",
    "attachment",
    "mail upload",
    "external.receiver",
    "channel=usb",
    "channel=bluetooth",
    "copied",
]


class LogParser:
    PARSER_REGISTRY: Dict[str, Type["TypedLogParser"]] = {}

    def parse(self, logs: str, log_type: str = "generic") -> List[ParsedLog]:
        parser_class = self.PARSER_REGISTRY.get(log_type, GenericLogParser)
        return parser_class().parse(logs)


class TypedLogParser:
    event_prefix = "generic"

    def parse(self, logs: str) -> List[ParsedLog]:
        lines = [line.strip() for line in logs.splitlines() if line.strip()]
        ip_counts = Counter(IP_RE.findall("\n".join(lines)))
        return [self._parse_line(line_no, line, ip_counts) for line_no, line in enumerate(lines, start=1)]

    def _parse_line(self, line_no: int, line: str, ip_counts: Counter) -> ParsedLog:
        source_ip = self.extract_source_ip(line)
        timestamp = self.extract_timestamp(line)
        severity = self.detect_severity(line)
        event_type = self.detect_event_type(line)

        return ParsedLog(
            line_no=line_no,
            timestamp=timestamp,
            source_ip=source_ip,
            severity=severity,
            event_type=event_type,
            raw_log=line,
            features=self.build_features(line, source_ip, ip_counts[source_ip]),
        )

    def extract_source_ip(self, line: str) -> str:
        for pattern in (
            r"\bsource_ip[=: ]+({ip})\b",
            r"\bsrc(?:_ip)?[=: ]+({ip})\b",
            r"\bSRC=({ip})\b",
            r"\bSourceNetworkAddress[=: ]+({ip})\b",
        ):
            match = re.search(pattern.format(ip=IP_RE.pattern.strip(r"\b")), line, re.IGNORECASE)
            if match:
                return match.group(1)
        ip_match = IP_RE.search(line)
        return ip_match.group(0) if ip_match else "unknown"

    def extract_timestamp(self, line: str) -> Optional[str]:
        iso_match = ISO_TIME_RE.search(line)
        if iso_match:
            return iso_match.group(0).replace("T", " ")

        apache_match = APACHE_TIME_RE.search(line)
        if apache_match:
            try:
                return datetime.strptime(apache_match.group(1), "%d/%b/%Y:%H:%M:%S").isoformat(sep=" ")
            except ValueError:
                return apache_match.group(1)

        syslog_match = SYSLOG_TIME_RE.search(line)
        if syslog_match:
            return syslog_match.group(1)

        return None

    def detect_severity(self, line: str) -> str:
        lowered = line.lower()
        for word, severity in SEVERITY_WORDS.items():
            if re.search(rf"\b{re.escape(word)}\b", lowered):
                return severity
        if any(term in lowered for term in SUSPICIOUS_TERMS):
            return "WARNING"
        return "INFO"

    def detect_event_type(self, line: str) -> str:
        lowered = line.lower()
        for event_type, keywords in EVENT_KEYWORDS.items():
            if any(keyword in lowered for keyword in keywords):
                return event_type
        return "general"

    def build_features(self, line: str, source_ip: str, repeated_ip_count: int) -> List[float]:
        lowered = line.lower()
        hour = 12
        timestamp = self.extract_timestamp(line)
        if timestamp:
            hour_match = re.search(r"\b(\d{2}):\d{2}:\d{2}\b", timestamp)
            if hour_match:
                hour = int(hour_match.group(1))

        login_attempts = max(repeated_ip_count, 1 if any(term in lowered for term in ["login", "auth", "ssh"]) else 0)
        session_level = min(10, max(1, len(line) // 40))
        file_access = int(any(term in lowered for term in ["file", "read", "open", "opened", "copy", "copied", "download", "attachment"]))
        file_delete = int(any(term in lowered for term in ["delete", "deleted", "remove", "rm "]))
        network_activity = min(10, 1 + sum(term in lowered for term in ["connect", "port", "tcp", "udp", "http", "dns"]))
        process_activity = min(10, sum(term in lowered for term in ["process", "cmd", "powershell", "bash", "exec"]))
        suspicious_cmd = int(any(term in lowered for term in ["powershell", "cmd.exe", "wget", "curl", "base64", "chmod"]))
        remote_login = int(any(term in lowered for term in ["ssh", "rdp", "remote"]))
        usb_activity = int("usb" in lowered or "removable" in lowered or "mtp" in lowered)

        return [
            float(login_attempts),
            float(hour),
            float(session_level),
            float(self.ip_to_number(source_ip)),
            float(file_access),
            float(file_delete),
            float(network_activity),
            float(process_activity),
            float(suspicious_cmd),
            float(remote_login),
            float(usb_activity),
        ]

    def ip_to_number(self, source_ip: str) -> int:
        try:
            return int(ipaddress.ip_address(source_ip))
        except ValueError:
            return 0

    def prefixed_event(self, event_type: str) -> str:
        return event_type if self.event_prefix == "generic" else f"{self.event_prefix}_{event_type}"


class GenericLogParser(TypedLogParser):
    event_prefix = "generic"


class AuthLogParser(TypedLogParser):
    event_prefix = "auth"

    def detect_severity(self, line: str) -> str:
        lowered = line.lower()
        if any(term in lowered for term in ["failed", "failure", "invalid user", "authentication failure", "denied"]):
            return "WARNING"
        if any(term in lowered for term in ["accepted", "success", "logged in", "login successful"]):
            return "INFO"
        return super().detect_severity(line)

    def detect_event_type(self, line: str) -> str:
        lowered = line.lower()
        if any(term in lowered for term in ["invalid user", "failed password", "authentication failure", "failed login"]):
            return self.prefixed_event("failed_login")
        if any(term in lowered for term in ["accepted password", "accepted publickey", "login successful", "logon success"]):
            return self.prefixed_event("successful_login")
        if any(term in lowered for term in ["sudo", "su:", "privilege", "elevat", "root"]):
            return self.prefixed_event("privilege_activity")
        if any(term in lowered for term in ["logout", "session closed", "logoff"]):
            return self.prefixed_event("logout")
        return self.prefixed_event("activity")


class FirewallLogParser(TypedLogParser):
    event_prefix = "firewall"

    def extract_source_ip(self, line: str) -> str:
        for pattern in (r"\bSRC=({ip})\b", r"\bsrc(?:_ip)?[=: ]+({ip})\b", r"\bsource[=: ]+({ip})\b"):
            match = re.search(pattern.format(ip=IP_RE.pattern.strip(r"\b")), line, re.IGNORECASE)
            if match:
                return match.group(1)
        return super().extract_source_ip(line)

    def detect_severity(self, line: str) -> str:
        lowered = line.lower()
        if any(term in lowered for term in ["deny", "denied", "drop", "dropped", "block", "blocked", "ufw block"]):
            return "WARNING"
        if any(term in lowered for term in ["allow", "accepted", "permit"]):
            return "INFO"
        return super().detect_severity(line)

    def detect_event_type(self, line: str) -> str:
        lowered = line.lower()
        if any(term in lowered for term in ["port scan", "scan detected", "nmap"]):
            return self.prefixed_event("port_scan")
        if any(term in lowered for term in ["deny", "denied", "drop", "dropped", "block", "blocked", "ufw block"]):
            return self.prefixed_event("blocked_connection")
        if any(term in lowered for term in ["allow", "accepted", "permit"]):
            return self.prefixed_event("allowed_connection")
        if any(term in lowered for term in ["tcp", "udp", "icmp", "proto="]):
            return self.prefixed_event("network_traffic")
        return self.prefixed_event("activity")

    def build_features(self, line: str, source_ip: str, repeated_ip_count: int) -> List[float]:
        features = super().build_features(line, source_ip, repeated_ip_count)
        lowered = line.lower()
        port_hits = len(re.findall(r"\b(?:dpt|spt|port)[=: ]+\d+\b", lowered))
        features[6] = float(min(10, features[6] + 2 + port_hits))
        features[0] = float(max(features[0], repeated_ip_count))
        return features


class EndpointLogParser(TypedLogParser):
    event_prefix = "endpoint"

    def detect_severity(self, line: str) -> str:
        lowered = line.lower()
        if any(term in lowered for term in ["malware", "ransomware", "quarantine", "encodedcommand", "credential dump"]):
            return "CRITICAL"
        if any(term in lowered for term in [
            "powershell",
            "cmd.exe",
            "file deleted",
            "usb storage",
            "privilege escalation",
            "mtptransfer",
            "obex transfer",
            "sent email",
            "attachment",
            "mail upload",
            "channel=usb",
            "channel=bluetooth",
        ]):
            return "WARNING"
        return super().detect_severity(line)

    def detect_event_type(self, line: str) -> str:
        lowered = line.lower()
        if any(term in lowered for term in ["powershell", "cmd.exe", "process created", "new process", "exec"]):
            return self.prefixed_event("process_activity")
        if any(term in lowered for term in ["sent email", "attachment", "mail upload", "smtp"]):
            return self.prefixed_event("outbound_transfer")
        if any(term in lowered for term in ["mtptransfer", "obex transfer", "channel=usb", "channel=bluetooth", "android device"]):
            return self.prefixed_event("device_transfer")
        if any(term in lowered for term in ["usb", "removable"]):
            return self.prefixed_event("usb_activity")
        if any(term in lowered for term in ["file deleted", "delete", "rm ", "chmod", "modified", "opened", "copied"]):
            return self.prefixed_event("file_activity")
        if any(term in lowered for term in ["malware", "ransomware", "trojan", "quarantine"]):
            return self.prefixed_event("malware_alert")
        if any(term in lowered for term in ["privilege", "sudo", "admin", "root"]):
            return self.prefixed_event("privilege_activity")
        return self.prefixed_event("activity")


class WindowsEventLogParser(TypedLogParser):
    event_prefix = "windows"

    EVENT_ID_TYPES = {
        "4624": "successful_logon",
        "4625": "failed_logon",
        "4634": "logoff",
        "4648": "explicit_credentials",
        "4672": "privileged_logon",
        "4688": "process_created",
        "4697": "service_installed",
        "4720": "user_created",
        "4726": "user_deleted",
        "4732": "group_membership_added",
        "1102": "audit_log_cleared",
    }

    def _json_payload(self, line: str) -> Dict:
        if not line.startswith("{"):
            return {}
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    def extract_source_ip(self, line: str) -> str:
        payload = self._json_payload(line)
        for key in ("IpAddress", "ipAddress", "src_ip", "source_ip", "SourceNetworkAddress"):
            value = payload.get(key)
            if isinstance(value, str) and IP_RE.search(value):
                return IP_RE.search(value).group(0)
        return super().extract_source_ip(line)

    def detect_severity(self, line: str) -> str:
        event_id = self._event_id(line)
        if event_id in {"1102", "4697", "4720", "4726", "4732"}:
            return "CRITICAL"
        if event_id in {"4625", "4648", "4672", "4688"}:
            return "WARNING"
        return super().detect_severity(line)

    def detect_event_type(self, line: str) -> str:
        event_id = self._event_id(line)
        if event_id in self.EVENT_ID_TYPES:
            return self.prefixed_event(self.EVENT_ID_TYPES[event_id])

        lowered = line.lower()
        if any(term in lowered for term in ["failed logon", "audit failure"]):
            return self.prefixed_event("failed_logon")
        if any(term in lowered for term in ["new process", "process created", "powershell", "cmd.exe"]):
            return self.prefixed_event("process_created")
        if any(term in lowered for term in ["special privileges", "administrator", "privileged"]):
            return self.prefixed_event("privileged_logon")
        return self.prefixed_event("activity")

    def _event_id(self, line: str) -> Optional[str]:
        payload = self._json_payload(line)
        for key in ("EventID", "event_id", "eventId", "id"):
            value = payload.get(key)
            if value is not None:
                return str(value)

        match = WINDOWS_EVENT_ID_RE.search(line)
        return match.group(1) if match else None


LogParser.PARSER_REGISTRY = {
    "generic": GenericLogParser,
    "auth": AuthLogParser,
    "firewall": FirewallLogParser,
    "endpoint": EndpointLogParser,
    "windows_event": WindowsEventLogParser,
}
