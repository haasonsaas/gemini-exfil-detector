#!/usr/bin/env python3
"""
File Context Enrichment - Track file sensitivity and ownership

Enriches findings with file metadata to determine:
- File sensitivity level (based on labels, folder location, ownership)
- Whether file was recently analyzed via Gemini
- File ownership patterns

Workaround for Gemini API limitation:
Since Gemini events don't expose doc_id, we correlate by:
1. Tracking all files a user interacts with in Drive
2. Matching recon timing with file access patterns
3. Flagging when exfiltrated file matches known-sensitive criteria
"""

import datetime as dt
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


@dataclass
class FileMetadata:
    doc_id: str
    title: str
    owner: str
    labels: List[str]
    sensitivity: str
    last_accessed: dt.datetime
    shared_externally: bool


class FileContextEnricher:
    def __init__(self, admin_service: Any, config: Dict):
        self.admin_service = admin_service
        self.logger = logging.getLogger(__name__)
        self.sensitive_labels = set(config.get("severity_overrides", {}).get("sensitive_labels", []))
        self.high_risk_folders = set(config.get("high_risk_folders", []))
        self.file_cache: Dict[str, FileMetadata] = {}

    def get_file_metadata(self, doc_id: str) -> Optional[FileMetadata]:
        if doc_id in self.file_cache:
            return self.file_cache[doc_id]

        try:
            drive_service = build("drive", "v3", credentials=self.admin_service._http.credentials)
            
            file_info = drive_service.files().get(
                fileId=doc_id,
                fields="id,name,owners,labels,labelInfo,permissions,modifiedTime",
                supportsAllDrives=True,
            ).execute()

            owner = file_info.get("owners", [{}])[0].get("emailAddress", "unknown")
            labels = self._extract_labels(file_info)
            sensitivity = self._determine_sensitivity(labels, owner)
            
            permissions = file_info.get("permissions", [])
            shared_externally = any(
                p.get("type") == "anyone" or "@" not in p.get("emailAddress", "")
                for p in permissions
            )

            metadata = FileMetadata(
                doc_id=doc_id,
                title=file_info.get("name", "Unknown"),
                owner=owner,
                labels=labels,
                sensitivity=sensitivity,
                last_accessed=dt.datetime.utcnow(),
                shared_externally=shared_externally,
            )

            self.file_cache[doc_id] = metadata
            return metadata

        except HttpError as e:
            if e.resp.status == 404:
                self.logger.warning(f"File not found: {doc_id}")
            else:
                self.logger.error(f"Error fetching file metadata for {doc_id}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error fetching file {doc_id}: {e}")
            return None

    def _extract_labels(self, file_info: Dict) -> List[str]:
        labels = []
        
        label_info = file_info.get("labelInfo", {}).get("labels", [])
        for label in label_info:
            labels.append(label.get("id", ""))
        
        if "labels" in file_info:
            for key, value in file_info["labels"].items():
                if value:
                    labels.append(key)
        
        return labels

    def _determine_sensitivity(self, labels: List[str], owner: str) -> str:
        label_lower = [l.lower() for l in labels]
        
        for sensitive_label in self.sensitive_labels:
            if any(sensitive_label.lower() in l for l in label_lower):
                return "high"
        
        if any(term in owner.lower() for term in ["exec", "ceo", "cfo", "finance"]):
            return "high"
        
        restricted_terms = ["confidential", "restricted", "internal", "sensitive", "private"]
        if any(term in l for term in restricted_terms for l in label_lower):
            return "medium"
        
        return "low"

    def enrich_finding(self, finding_dict: Dict, doc_id: Optional[str]) -> Dict:
        if not doc_id:
            return finding_dict

        metadata = self.get_file_metadata(doc_id)
        if not metadata:
            return finding_dict

        finding_dict["file_context"] = {
            "sensitivity": metadata.sensitivity,
            "labels": metadata.labels,
            "owner": metadata.owner,
            "shared_externally_before": metadata.shared_externally,
        }

        if metadata.sensitivity == "high":
            if finding_dict["severity"] == "medium":
                finding_dict["severity"] = "high"
                finding_dict["reason"] += " (high-sensitivity file)"
            elif finding_dict["severity"] == "low":
                finding_dict["severity"] = "medium"
                finding_dict["reason"] += " (high-sensitivity file)"

        return finding_dict

    def check_file_in_recon_window(
        self,
        actor: str,
        doc_id: str,
        exfil_time: dt.datetime,
        recon_files: List[str],
    ) -> bool:
        """
        Check if exfiltrated file was likely reconned (even without direct doc_id from Gemini).
        Uses heuristics: file in recent activity + temporal proximity.
        """
        if doc_id in recon_files:
            return True

        metadata = self.get_file_metadata(doc_id)
        if not metadata:
            return False

        time_delta = (exfil_time - metadata.last_accessed).total_seconds() / 60
        if 0 <= time_delta <= 30:
            return True

        return False
