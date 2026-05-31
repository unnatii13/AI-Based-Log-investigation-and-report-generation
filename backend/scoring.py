import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

import joblib
import numpy as np

from .domain import ParsedLog, ScoredEvent
from .log_parser import SUSPICIOUS_TERMS


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "ml_model")
MODEL_PATH = os.path.join(MODEL_DIR, "attack_detection_model.h5")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")


class RiskScorer(ABC):
    @abstractmethod
    def score(self, parsed_log: ParsedLog) -> Dict[str, Optional[float]]:
        raise NotImplementedError


class LstmRiskScorer(RiskScorer):
    _cached_model = None
    _cached_scaler = None
    _cached_error = None

    def __init__(self, model_path=MODEL_PATH, scaler_path=SCALER_PATH):
        self.model_path = model_path
        self.scaler_path = scaler_path

    def score(self, parsed_log: ParsedLog) -> Dict[str, Optional[float]]:
        if not self._load_assets():
            return {"score": None, "source": "heuristic", "error": self._cached_error}

        try:
            raw_array = np.array(parsed_log.features, dtype=np.float32).reshape(1, -1)
            scaled = self._cached_scaler.transform(raw_array)
            reshaped = scaled.reshape(1, 1, 11)
            score = float(self._cached_model.predict(reshaped, verbose=0)[0][0])
            return {"score": round(score, 4), "source": "lstm_model", "error": None}
        except Exception as exc:
            return {"score": None, "source": "heuristic", "error": str(exc)}

    def score_many(self, parsed_logs: List[ParsedLog]) -> List[Dict[str, Optional[float]]]:
        if not parsed_logs:
            return []
        if not self._load_assets():
            return [{"score": None, "source": "heuristic", "error": self._cached_error} for _ in parsed_logs]

        try:
            raw_array = np.array([parsed_log.features for parsed_log in parsed_logs], dtype=np.float32)
            scaled = self._cached_scaler.transform(raw_array)
            reshaped = scaled.reshape(len(parsed_logs), 1, 11)
            predictions = self._cached_model.predict(reshaped, verbose=0).reshape(-1)
            return [{"score": round(float(score), 4), "source": "lstm_model", "error": None} for score in predictions]
        except Exception as exc:
            return [{"score": None, "source": "heuristic", "error": str(exc)} for _ in parsed_logs]

    def _load_assets(self) -> bool:
        if LstmRiskScorer._cached_model is not None and LstmRiskScorer._cached_scaler is not None:
            return True

        try:
            from tensorflow.keras.models import load_model

            LstmRiskScorer._cached_scaler = joblib.load(self.scaler_path)
            LstmRiskScorer._cached_model = load_model(self.model_path, compile=False)
            LstmRiskScorer._cached_error = None
            return True
        except Exception as exc:
            LstmRiskScorer._cached_error = str(exc)
            return False


class HeuristicRiskScorer(RiskScorer):
    TRANSFER_TERMS = (
        "mtptransfer",
        "obex transfer",
        "sent email",
        "attachment",
        "mail upload",
        "channel=usb",
        "channel=bluetooth",
        "android device",
    )
    EXFIL_TERMS = (
        "external.receiver",
        "smtp mail upload",
        "sent email to external",
        "attachment=",
    )

    def score(self, parsed_log: ParsedLog) -> Dict[str, Optional[float]]:
        lowered = parsed_log.raw_log.lower()
        score = 0.08
        repeated_ip_count = max(int(parsed_log.features[0]), 1)
        score += min(repeated_ip_count * 0.05, 0.25)
        score += sum(0.08 for term in SUSPICIOUS_TERMS if term in lowered)
        if parsed_log.event_type == "firewall_port_scan" or any(term in lowered for term in ["port scan", "scan detected", "nmap"]):
            score += 0.32
        if any(term in lowered for term in self.TRANSFER_TERMS):
            score += 0.22
        if any(term in lowered for term in self.EXFIL_TERMS):
            score += 0.28

        if parsed_log.severity in {"ALERT", "CRITICAL"}:
            score += 0.28
        elif parsed_log.severity == "ERROR":
            score += 0.16
        elif parsed_log.severity == "WARNING":
            score += 0.1

        return {"score": round(min(score, 0.99), 4), "source": "heuristic", "error": None}


class CompositeRiskScorer(RiskScorer):
    def __init__(self, primary_scorer: RiskScorer, fallback_scorer: RiskScorer):
        self.primary_scorer = primary_scorer
        self.fallback_scorer = fallback_scorer

    def score(self, parsed_log: ParsedLog) -> Dict[str, Optional[float]]:
        primary = self.primary_scorer.score(parsed_log)
        fallback = self.fallback_scorer.score(parsed_log)

        if primary["score"] is None:
            return fallback

        return {
            "score": max(primary["score"], fallback["score"]),
            "source": primary["source"],
            "error": primary["error"],
        }

    def score_many(self, parsed_logs: List[ParsedLog]) -> List[Dict[str, Optional[float]]]:
        if hasattr(self.primary_scorer, "score_many"):
            primary_results = self.primary_scorer.score_many(parsed_logs)
        else:
            primary_results = [self.primary_scorer.score(parsed_log) for parsed_log in parsed_logs]

        fallback_results = [self.fallback_scorer.score(parsed_log) for parsed_log in parsed_logs]
        combined_results = []

        for primary, fallback in zip(primary_results, fallback_results):
            if primary["score"] is None:
                combined_results.append(fallback)
            else:
                combined_results.append(
                    {
                        "score": max(primary["score"], fallback["score"]),
                        "source": primary["source"],
                        "error": primary["error"],
                    }
                )

        return combined_results


class EventClassifier:
    suspicious_threshold = 0.35
    attack_threshold = 0.7
    dangerous_action_threshold = 0.45

    def classify(self, parsed_log: ParsedLog, score: float) -> str:
        lowered = parsed_log.raw_log.lower()
        if self._is_clear_attack(lowered, parsed_log):
            return "ATTACK"

        if self._is_clear_normal(lowered, parsed_log):
            return "NORMAL"

        if (
            score >= self.attack_threshold
            or parsed_log.severity in {"ALERT", "CRITICAL"}
            or (score >= self.dangerous_action_threshold and self._has_dangerous_action(lowered))
        ):
            return "ATTACK"
        if score >= self.suspicious_threshold or parsed_log.severity in {"ERROR", "WARNING"}:
            return "SUSPICIOUS"
        return "NORMAL"

    def _is_clear_attack(self, lowered: str, parsed_log: ParsedLog) -> bool:
        if parsed_log.event_type == "firewall_port_scan":
            return True

        attack_patterns = [
            "powershell.exe -encodedcommand",
            "encodedcommand",
            "sqlmap",
            "union select",
            "' or '1'='1",
            "port scan",
            "scan detected",
            "nmap",
            "file_deleted",
            "deleted /var/log",
            "ransomware",
            "malware",
            "sent email to external",
            "smtp mail upload",
        ]
        if any(pattern in lowered for pattern in attack_patterns):
            return True
        return parsed_log.severity == "CRITICAL" and any(term in lowered for term in ["delete", "deleted", "powershell"])

    def _is_clear_normal(self, lowered: str, parsed_log: ParsedLog) -> bool:
        normal_patterns = [
            "started daily",
            "accepted password",
            "allow in=",
            '"get /index.html http/1.1" 200',
            " status=200",
        ]
        blocked_by_bad_terms = any(
            term in lowered
            for term in [
                "failed",
                "invalid user",
                "ufw block",
                "denied",
                "sqlmap",
                "encodedcommand",
                "critical",
                "deleted",
                "mtptransfer",
                "obex transfer",
                "sent email",
                "attachment",
                "mail upload",
                "channel=usb",
                "channel=bluetooth",
            ]
        )
        return parsed_log.severity == "INFO" and not blocked_by_bad_terms and any(
            pattern in lowered for pattern in normal_patterns
        )

    def _has_dangerous_action(self, lowered: str) -> bool:
        return any(term in lowered for term in [
            "delete",
            "powershell",
            "cmd.exe",
            "sudo",
            "malware",
            "mtptransfer",
            "obex transfer",
            "sent email",
            "attachment",
            "mail upload",
            "channel=usb",
            "channel=bluetooth",
        ])

    def explain(self, parsed_log: ParsedLog, score: float, verdict: str) -> str:
        reasons = []
        lowered = parsed_log.raw_log.lower()

        if parsed_log.severity in {"ALERT", "CRITICAL", "ERROR", "WARNING"}:
            reasons.append(f"severity={parsed_log.severity}")
        if parsed_log.source_ip != "unknown":
            reasons.append(f"source_ip={parsed_log.source_ip}")
        if parsed_log.event_type != "general":
            reasons.append(f"event_type={parsed_log.event_type}")
        if any(term in lowered for term in ["failed", "denied", "unauthorized"]):
            reasons.append("authentication or access failure")
        if any(term in lowered for term in ["powershell", "encodedcommand", "cmd.exe", "wget", "curl", "base64"]):
            reasons.append("suspicious command activity")
        if any(term in lowered for term in ["sqlmap", "union select", "' or '1'='1"]):
            reasons.append("web attack signature")
        if parsed_log.event_type == "firewall_port_scan" or any(term in lowered for term in ["port scan", "scan detected", "nmap"]):
            reasons.append("port scan activity")
        if any(term in lowered for term in ["delete", "deleted", "rm "]):
            reasons.append("destructive file activity")
        if any(term in lowered for term in ["mtptransfer", "channel=usb", "android device"]):
            reasons.append("file movement to removable/mobile device")
        if any(term in lowered for term in ["obex transfer", "channel=bluetooth"]):
            reasons.append("Bluetooth file transfer")
        if any(term in lowered for term in ["sent email", "attachment", "mail upload", "smtp"]):
            reasons.append("outbound file transfer")
        if parsed_log.features[0] > 3:
            reasons.append("repeated activity from same source")

        reason_text = ", ".join(reasons) if reasons else "no high-risk indicators found"
        return f"{verdict}: {reason_text}; risk={round(score * 100, 2)}%"


class EventScoringService:
    def __init__(self, risk_scorer: RiskScorer, classifier: EventClassifier):
        self.risk_scorer = risk_scorer
        self.classifier = classifier

    def score_event(self, parsed_log: ParsedLog) -> ScoredEvent:
        score_result = self.risk_scorer.score(parsed_log)
        return self._build_scored_event(parsed_log, score_result)

    def score_events(self, parsed_logs: List[ParsedLog]) -> List[ScoredEvent]:
        if len(parsed_logs) <= 2:
            fast_scorer = HeuristicRiskScorer()
            return [
                self._build_scored_event(
                    parsed_log,
                    {
                        **fast_scorer.score(parsed_log),
                        "source": "fast_rules",
                    },
                )
                for parsed_log in parsed_logs
            ]

        if hasattr(self.risk_scorer, "score_many"):
            score_results = self.risk_scorer.score_many(parsed_logs)
        else:
            score_results = [self.risk_scorer.score(parsed_log) for parsed_log in parsed_logs]
        return [self._build_scored_event(parsed_log, score_result) for parsed_log, score_result in zip(parsed_logs, score_results)]

    def _build_scored_event(self, parsed_log: ParsedLog, score_result: Dict[str, Optional[float]]) -> ScoredEvent:
        score = float(score_result["score"] or 0)
        verdict = self.classifier.classify(parsed_log, score)

        return ScoredEvent(
            line_no=parsed_log.line_no,
            timestamp=parsed_log.timestamp,
            source_ip=parsed_log.source_ip,
            severity=parsed_log.severity,
            event_type=parsed_log.event_type,
            risk_score=round(score * 100, 2),
            verdict=verdict,
            explanation=self.classifier.explain(parsed_log, score, verdict),
            model_source=str(score_result["source"]),
            model_error=score_result["error"],
            raw_log=parsed_log.raw_log,
            features=parsed_log.features,
        )
