"""
NovaLink Subscription Manager
Fetches active subscription URLs with bounded concurrency, HTTP timeout handling,
status code verification, Base64/JSON/URI-list parsing, deduplication against existing profiles,
preservation of previous valid profiles on fetch failure, and strict URL/token redaction in logs.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional, Callable
import time
import urllib.request
import urllib.error
import urllib.parse
import ssl

from .models import Subscription, Profile
from .parser import decode_subscription_content


def redact_url(url: str) -> str:
    """
    Masks sensitive paths, query tokens, and credentials from subscription URLs
    before writing to logs, error messages, or diagnostic outputs.
    Example: https://sub.provider.com/api/v1/client/subscribe?token=secret123 -> https://sub.provider.com/***[REDACTED]***
    """
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or "unknown-host"
        port_part = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{host}{port_part}/***[REDACTED]***"
    except Exception:
        return "***[REDACTED_URL]***"


@dataclass
class SubscriptionUpdateResult:
    subscription_id: str
    subscription_name: str
    success: bool
    added_count: int = 0
    updated_count: int = 0
    duplicate_count: int = 0
    invalid_count: int = 0
    total_valid_in_feed: int = 0
    preserved_previous: bool = False
    error_message: str = ""
    elapsed_ms: int = 0


class SubscriptionManager:
    """
    Handles updating single or multiple subscriptions with bounded concurrency,
    timeout control, and safe preservation of existing profiles on failure.
    """

    def __init__(self, timeout_sec: float = 10.0, max_workers: int = 3):
        self.timeout_sec = timeout_sec
        self.max_workers = max(1, min(max_workers, 8))

    def fetch_url_content(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Fetches raw subscription text from an HTTP/HTTPS URL.
        Enforces TLS certificate verification and timeout.
        Returns (content, None) on HTTP 200, or (None, sanitized_error_message) on failure.
        """
        parsed = urllib.parse.urlsplit(url.strip())
        if parsed.scheme.lower() not in ("http", "https"):
            return None, "Unsupported URL scheme (only http:// and https:// are allowed)."
        if not parsed.hostname:
            return None, "Invalid subscription URL: missing hostname."

        safe_label = redact_url(url)
        req = urllib.request.Request(
            url.strip(),
            headers={
                "User-Agent": "NovaLink-Win7/1.2.0 (Xray-core Compatible)",
                "Accept": "text/plain, application/json, */*",
            },
            method="GET",
        )

        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec, context=ctx) as resp:
                status = getattr(resp, "status", resp.getcode())
                if status != 200:
                    return None, f"HTTP status {status} from {safe_label}"
                raw_bytes = resp.read(5 * 1024 * 1024)  # Cap at 5 MB for security
                return raw_bytes.decode("utf-8", errors="replace"), None
        except urllib.error.HTTPError as he:
            return None, f"HTTP Error {he.code} ({he.reason}) when fetching {safe_label}"
        except urllib.error.URLError as ue:
            return None, f"Network/TLS Error ({ue.reason}) when fetching {safe_label}"
        except TimeoutError:
            return None, f"Connection timed out after {self.timeout_sec}s for {safe_label}"
        except Exception as exc:
            return None, f"Unexpected error fetching {safe_label}: {type(exc).__name__}"

    def update_all_subscriptions(
        self,
        subscriptions: List[Subscription],
        existing_profiles: List[Profile],
        progress_callback: Optional[Callable[[int, int, SubscriptionUpdateResult], None]] = None,
    ) -> Tuple[List[Profile], List[SubscriptionUpdateResult]]:
        """
        Updates all enabled subscriptions concurrently (up to self.max_workers).
        - Manual user profiles (`subscription_id == "manual"`) are never modified or deleted.
        - Disabled subscriptions retain their existing profiles untouched.
        - If an enabled subscription fails to download or yields 0 valid profiles, its previous
          valid profiles are preserved intact and `preserved_previous=True` is set.
        - Deduplicates profiles both within each feed and across existing profiles using
          `Profile.fingerprint_key()`.
        """
        active_subs = [s for s in subscriptions if s.enabled]
        if not active_subs:
            return list(existing_profiles), []

        # Fetch all active subscriptions in bounded thread pool
        fetched_Payloads: Dict[str, Tuple[Optional[str], Optional[str], int]] = {}

        def _fetch_task(sub: Subscription) -> Tuple[str, Optional[str], Optional[str], int]:
            t0 = time.monotonic()
            content, err = self.fetch_url_content(sub.url)
            elapsed = int((time.monotonic() - t0) * 1000)
            return sub.id, content, err, elapsed

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(_fetch_task, s): s for s in active_subs}
            for fut in as_completed(futures):
                sub_id, content, err, elapsed = fut.result()
                fetched_Payloads[sub_id] = (content, err, elapsed)

        # Reconcile profiles deterministically
        # Keep manual profiles and profiles belonging to disabled subscriptions first
        active_sub_ids = {s.id for s in active_subs}
        retained_profiles: List[Profile] = [
            p for p in existing_profiles if p.subscription_id not in active_sub_ids
        ]
        global_fingerprints = {p.fingerprint_key(): p for p in retained_profiles}

        # Group previous profiles of active subscriptions by subscription_id
        prev_by_sub: Dict[str, List[Profile]] = {s.id: [] for s in active_subs}
        for p in existing_profiles:
            if p.subscription_id in prev_by_sub:
                prev_by_sub[p.subscription_id].append(p)

        results: List[SubscriptionUpdateResult] = []
        completed_idx = 0

        for sub in active_subs:
            completed_idx += 1
            content, fetch_err, elapsed_ms = fetched_Payloads[sub.id]
            prev_list = prev_by_sub.get(sub.id, [])
            prev_by_fp = {p.fingerprint_key(): p for p in prev_list}

            if fetch_err is not None or content is None:
                # Preserve previous valid profiles
                for p in prev_list:
                    if p.fingerprint_key() not in global_fingerprints:
                        retained_profiles.append(p)
                        global_fingerprints[p.fingerprint_key()] = p

                sub.last_status = "Failed (Previous Profiles Preserved)"
                sub.last_error = fetch_err or "Empty response"
                res = SubscriptionUpdateResult(
                    subscription_id=sub.id,
                    subscription_name=sub.name,
                    success=False,
                    preserved_previous=len(prev_list) > 0,
                    error_message=sub.last_error,
                    elapsed_ms=elapsed_ms,
                )
                results.append(res)
                if progress_callback:
                    progress_callback(completed_idx, len(active_subs), res)
                continue

            parsed_profiles, parse_errors = decode_subscription_content(content, subscription_id=sub.id)
            invalid_count = len(parse_errors)

            if not parsed_profiles:
                # Feed returned 0 valid profiles — preserve previous profiles
                for p in prev_list:
                    if p.fingerprint_key() not in global_fingerprints:
                        retained_profiles.append(p)
                        global_fingerprints[p.fingerprint_key()] = p

                err_summary = "; ".join(parse_errors[:3]) if parse_errors else "No valid profiles found in feed."
                sub.last_status = "Failed (0 Valid Profiles - Preserved Previous)"
                sub.last_error = err_summary
                sub.last_invalid_count = invalid_count
                res = SubscriptionUpdateResult(
                    subscription_id=sub.id,
                    subscription_name=sub.name,
                    success=False,
                    invalid_count=invalid_count,
                    preserved_previous=len(prev_list) > 0,
                    error_message=err_summary,
                    elapsed_ms=elapsed_ms,
                )
                results.append(res)
                if progress_callback:
                    progress_callback(completed_idx, len(active_subs), res)
                continue

            added = 0
            updated = 0
            duplicates = 0
            accepted_for_sub: List[Profile] = []

            for cand in parsed_profiles:
                fp = cand.fingerprint_key()
                if fp in global_fingerprints:
                    duplicates += 1
                    continue

                if fp in prev_by_fp:
                    # Preserve historical ID and last latency measurement while updating name/group
                    old_prof = prev_by_fp[fp]
                    cand.id = old_prof.id
                    cand.latency_ms = old_prof.latency_ms
                    cand.last_test_status = old_prof.last_test_status
                    cand.last_test_method = old_prof.last_test_method
                    cand.last_test_time = old_prof.last_test_time
                    updated += 1
                else:
                    added += 1

                cand.group = sub.name
                accepted_for_sub.append(cand)
                retained_profiles.append(cand)
                global_fingerprints[fp] = cand

            sub.last_update_time = time.time()
            sub.last_status = "Updated"
            sub.last_error = "; ".join(parse_errors[:2]) if parse_errors else ""
            sub.profile_count = len(accepted_for_sub)
            sub.last_added_count = added
            sub.last_updated_count = updated
            sub.last_duplicate_count = duplicates
            sub.last_invalid_count = invalid_count

            res = SubscriptionUpdateResult(
                subscription_id=sub.id,
                subscription_name=sub.name,
                success=True,
                added_count=added,
                updated_count=updated,
                duplicate_count=duplicates,
                invalid_count=invalid_count,
                total_valid_in_feed=len(accepted_for_sub),
                preserved_previous=False,
                error_message=sub.last_error,
                elapsed_ms=elapsed_ms,
            )
            results.append(res)
            if progress_callback:
                progress_callback(completed_idx, len(active_subs), res)

        return retained_profiles, results
