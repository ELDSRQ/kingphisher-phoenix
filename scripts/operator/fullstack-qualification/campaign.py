"""Reviewed-direct launches over HTTP, real SMTP/queue/worker observation."""

from __future__ import annotations

import html
import json
import re
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
from evidence import QualificationFailure, percentile
from sqlalchemy import create_engine, text
from stack import Stack


class Campaigns:
    def __init__(self, stack: Stack, services: dict[str, Any], endpoints: dict[str, str]) -> None:
        self.stack, self.evidence, self.services, self.endpoints = stack, stack.evidence, services, endpoints
        self.latencies: list[float] = []
        self.principals = {name: str(uuid.uuid4()) for name in ("author", "security", "privacy")}
        self.client = httpx.Client(timeout=10, trust_env=False, follow_redirects=False)
        self.engine = create_engine(stack.connection_urls(services), connect_args={"connect_timeout": 3})
        self.campaigns: list[dict[str, Any]] = []

    def token(self, person: str) -> str:
        return jwt.encode(
            {
                "sub": self.principals[person],
                "roles": ["administrator"],
                "iss": "http://localhost:8443/realms/kingphisher",
                "aud": "kp-operator-api",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
            },
            self.stack.secrets["console"],
            algorithm="HS256",
        )

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        person: str = "author",
        expected: tuple[int, ...] = (200, 201, 202),
        measure: bool = True,
    ) -> Any:
        self.evidence.remaining()
        started = time.monotonic()
        response = self.client.request(
            method,
            self.endpoints["operator"] + "/api/v1" + path,
            headers={"Authorization": f"Bearer {self.token(person)}"},
            json=body,
        )
        elapsed = time.monotonic() - started
        if measure:
            self.latencies.append(elapsed)
        self.evidence.event("api_observation", method=method, route=path, status=response.status_code, seconds=elapsed)
        if response.status_code not in expected:
            # Do not echo validation details, which may reflect credentials.
            raise QualificationFailure(f"API request failed: {method} {path} status={response.status_code}")
        return response.json()

    def ready(self, prefix: str) -> None:
        deadline = time.monotonic() + self.evidence.remaining(self.evidence.profile.readiness_seconds)
        while time.monotonic() < deadline:
            self.evidence.remaining()
            if any(process.poll() is not None for process, _ in self.stack.processes.values()):
                raise QualificationFailure("owned application exited during readiness")
            try:
                api_ready = all(
                    self.client.get(url + "/healthz").is_success
                    for name, url in self.endpoints.items()
                    if name in {"operator", "tracking"}
                )
                api_ready = api_ready and self.client.get(self.endpoints["mailpit"] + "/api/v1/info").is_success
                roles = []
                for role in ("delivery", "retention", "audit-anchor"):
                    log = self.evidence.root / f"{prefix}-worker-{role}.log"
                    events = [json.loads(line) for line in log.read_text().splitlines() if line.startswith("{")]
                    matching = [
                        event
                        for event in events
                        if event.get("event") == "worker_role_readiness" and event.get("role") == role
                    ]
                    roles.append(bool(matching and matching[-1].get("ready") is True))
                if api_ready and all(roles):
                    self.evidence.event("services_ready", prefix=prefix)
                    return
            except (httpx.HTTPError, json.JSONDecodeError):
                pass
            time.sleep(0.25)
        raise QualificationFailure("application or worker readiness deadline exceeded")

    def fixtures(self) -> None:
        from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
        from kp_database.models import CampaignPattern, CipherText, TemplateVersion, VerifiedDomain
        from kp_database.session import make_session_factory
        from kp_domain_models import models as dm

        CipherText.configure_keyring("primary", bytes.fromhex(self.stack.secrets["cipher"]), {})
        pattern_id, template_id = uuid.uuid4(), uuid.uuid4()
        now = datetime.now(UTC)
        with make_session_factory(self.engine)() as session:
            session.add(
                VerifiedDomain(
                    verified_domain_id=uuid.uuid4(),
                    domain="qualification.test",
                    challenge_token=uuid.uuid4().hex,
                    verified_at=now,
                    verified_by=uuid.UUID(self.principals["author"]),
                    active=True,
                )
            )
            session.add(
                CampaignPattern(
                    campaign_pattern_id=pattern_id,
                    lure_category=dm.LureCategory.INVOICE,
                    confidence=dm.Confidence.HIGH,
                    approval_state=dm.PatternApprovalState.APPROVED,
                    approved_by=uuid.UUID(self.principals["security"]),
                    approved_at=now,
                )
            )
            session.add(
                TemplateVersion(
                    template_version_id=template_id,
                    generator_version="qualification-fixture",
                    prompt_template_version="qualification-fixture",
                    model_id="synthetic-no-model",
                    input_hash="0" * 64,
                    raw_proposal={"requested_by": self.principals["author"]},
                    subject=f"Synthetic qualification {self.evidence.run_id}",
                    plain_text=f"Review this training exercise: {TRAINING_URL_PLACEHOLDER}",
                    safe_html=f'<p>Training exercise</p><a href="{TRAINING_URL_PLACEHOLDER}">Review</a>',
                    warning_cues=[],
                    cue_manifest={},
                    approval_state=dm.TemplateApprovalState.DRAFT,
                )
            )
            session.commit()
        self.request(
            "POST",
            f"/templates/{template_id}/decision",
            {"decision": "approved", "rationale": "Independent synthetic qualification review"},
            "security",
        )
        resource = self.request(
            "POST",
            "/training-resources",
            {
                "title": "Synthetic qualification lesson",
                "content": "Verify unexpected requests using a known channel.",
                "knowledge_question": "What is the safe next step?",
                "knowledge_options": ["Verify independently", "Act immediately"],
                "knowledge_answer_index": 0,
            },
        )
        resource_id = resource["training_resource_id"]
        self.request("POST", f"/training-resources/{resource_id}/submit", {})
        self.request(
            "POST",
            f"/training-resources/{resource_id}/decision",
            {"decision": "approved", "rationale": "Independent synthetic lesson review"},
            "security",
        )
        roe = self.request(
            "POST",
            "/roe",
            {
                "authorizing_party": "Synthetic task-owned qualification",
                "terms": "Only this isolated .test roster and loopback SMTP sink are authorized.",
                "window_start": (now - timedelta(minutes=1)).isoformat(),
                "window_end": (now + timedelta(hours=2)).isoformat(),
                "target_domains": ["qualification.test"],
            },
        )
        self.fixture_ids = dict(
            pattern=str(pattern_id), template=str(template_id), resource=resource_id, roe=roe["roe_id"]
        )
        self.evidence.json(
            "fixture-scope.json",
            {
                **self.fixture_ids,
                "principals": self.principals,
                "dns_evidence": "synthetic prerequisite",
                "cue_obligation": "cue-less template",
                "human_acceptance": False,
            },
        )

    def launch(self, size: int, label: str) -> dict[str, Any]:
        now = datetime.now(UTC)
        roster = {
            "roe_id": self.fixture_ids["roe"],
            "target_domain": "qualification.test",
            "roster_name": f"{self.evidence.run_id}-{label}",
            "csv_text": "mailbox,display_name,department\n"
            + "".join(f"{label}-{i}@qualification.test,Synthetic {i},Qualification\n" for i in range(size)),
        }
        preview = self.request("POST", "/recipients/import/preview", roster)
        imported = self.request(
            "POST", "/recipients/import/apply", {**roster, "preview_digest": preview["preview_digest"]}
        )
        campaign = self.request(
            "POST",
            "/campaigns",
            {
                "delivery_mode": "reviewed_direct",
                "pattern_id": self.fixture_ids["pattern"],
                "template_version_id": self.fixture_ids["template"],
                "training_resource_id": self.fixture_ids["resource"],
                "title": f"Qualification {label}",
                "sender_mailbox": "training@qualification.test",
                "training_domain": "qualification.test",
                "schedule_start": (now - timedelta(seconds=10)).isoformat(),
                "schedule_end": (now + timedelta(hours=1)).isoformat(),
                "max_recipients": size,
            },
        )
        identifier = campaign["campaign_id"]
        self.request(
            "PUT",
            f"/campaigns/{identifier}/audience",
            {"roe_id": self.fixture_ids["roe"], "group_ids": [imported["roster"]["audience_group_id"]]},
        )
        audience = self.request("GET", f"/campaigns/{identifier}/audience/preview")
        if audience.get("included_count") != size:
            raise QualificationFailure("reviewed audience count mismatch")
        self.request("POST", f"/campaigns/{identifier}/confirm", {"preview_hash": audience["preview_hash"]})
        for lane, person in (("security", "security"), ("privacy", "privacy")):
            self.request(
                "POST",
                f"/campaigns/{identifier}/approvals/{lane}",
                {"decision": "approved", "rationale": "Exact synthetic roster/content review"},
                person,
            )
        result = self.request("POST", f"/campaigns/{identifier}/send")
        self.request("POST", f"/campaigns/{identifier}/send", expected=(409,))
        observation = {"id": identifier, "size": size, "label": label, "send": result}
        self.campaigns.append(observation)
        self.evidence.event("reviewed_direct_sent", **observation)
        return observation

    def observe(self, campaign: dict[str, Any]) -> dict[str, int]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT send_state::text,count(*) FROM recipient_assignments "
                    "WHERE campaign_id=:id GROUP BY send_state"
                ),
                {"id": uuid.UUID(campaign["id"])},
            ).all()
        states = {str(state): int(count) for state, count in rows}
        self.evidence.event("assignment_observation", campaign_id=campaign["id"], states=states)
        return states

    def drain(self, campaign: dict[str, Any], *, uncertain: bool = False) -> dict[str, int]:
        deadline = time.monotonic() + self.evidence.remaining(self.evidence.profile.drain_seconds)
        while time.monotonic() < deadline:
            states = self.observe(campaign)
            if sum(states.values()) != campaign["size"]:
                raise QualificationFailure("assignment cardinality differs from the exact reviewed roster")
            normalized = {key.lower(): value for key, value in states.items()}
            completed = sum(normalized.get(key, 0) for key in ("accepted", "delivered", "indeterminate"))
            if completed == campaign["size"]:
                if not uncertain and normalized.get("indeterminate", 0):
                    raise QualificationFailure("normal SMTP send became indeterminate")
                if uncertain and normalized.get("indeterminate", 0) != campaign["size"]:
                    raise QualificationFailure(
                        "post-acceptance disconnect did not produce exact uncertainty disposition"
                    )
                report = self.request("GET", f"/campaigns/{campaign['id']}/report", measure=False)
                self.evidence.json(f"report-{campaign['label']}.json", report)
                return states
            if any(key in normalized for key in ("failed", "skipped")):
                raise QualificationFailure("campaign contains failed or skipped assignments")
            if self.delivery_dead_letters():
                raise QualificationFailure("delivery exhausted retries while campaign assignments remain unresolved")
            self.evidence.remaining()
            time.sleep(0.25)
        raise QualificationFailure("campaign drain deadline exceeded")

    def delivery_dead_letters(self) -> int:
        """Read only this isolated run's delivery failure count; never replay."""
        from kp_contracts.queue import JobQueue

        queue = JobQueue(self.endpoints["redis"] + "?socket_timeout=2&socket_connect_timeout=2")
        try:
            return int(queue.queue_stats("deliver")["dead_letter"] or 0)
        finally:
            queue.close()

    def require_fault_observed(self, campaign: dict[str, Any], mode: str) -> None:
        deadline = time.monotonic() + self.evidence.remaining(15)
        recipient = f"{campaign['label']}-0@qualification.test"
        path = self.evidence.root / "smtp-journal.jsonl"
        while time.monotonic() < deadline:
            events = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
            matches = [row for row in events if row.get("mode") == mode and recipient in row.get("recipients", [])]
            if matches:
                if mode == "disconnect_after_accept" and sum(bool(row.get("accepted")) for row in matches) != 1:
                    raise QualificationFailure("uncertain SMTP message did not have exactly one sink acceptance")
                self.evidence.event(
                    "smtp_fault_observed", mode=mode, campaign_id=campaign["id"], observations=len(matches)
                )
                return
            self.evidence.remaining()
            time.sleep(0.05)
        raise QualificationFailure("declared SMTP fault mode was never observed")

    def delay_boundary(self, campaign: dict[str, Any], event: str) -> float:
        deadline = time.monotonic() + self.evidence.remaining(15)
        recipient = f"{campaign['label']}-0@qualification.test"
        path = self.evidence.root / "smtp-journal.jsonl"
        while time.monotonic() < deadline:
            rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
            matches = [
                row
                for row in rows
                if row.get("event") == event and row.get("mode") == "delay" and recipient in row.get("recipients", [])
            ]
            if matches:
                return float(matches[0]["at"])
            time.sleep(0.02)
        raise QualificationFailure("SMTP delay boundary was not observed")

    def sink_counts(self, expected: set[str] | None = None) -> int:
        path = self.evidence.root / "smtp-journal.jsonl"
        events = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        recipients = [recipient for event in events if event.get("accepted") for recipient in event["recipients"]]
        if len(recipients) != len(set(recipients)):
            raise QualificationFailure("duplicate SMTP sink acceptance observed")
        if expected is not None and set(recipients) != expected:
            raise QualificationFailure("SMTP envelope acceptance scope differs from the exact reviewed roster")
        return len(recipients)

    def verify_sink_accounting(self) -> int:
        expected = {
            f"{campaign['label']}-{i}@qualification.test"
            for campaign in self.campaigns
            for i in range(campaign["size"])
        }
        observed = []
        for offset in range(0, 20000, 200):
            response = self.client.get(
                self.endpoints["mailpit"] + "/api/v1/messages", params={"start": offset, "limit": 200}
            )
            response.raise_for_status()
            rows = response.json()["messages"]
            for row in rows:
                addresses = [item["Address"] for item in row.get("To", [])]
                if len(addresses) != 1:
                    raise QualificationFailure("SMTP sink message has unexpected recipient cardinality")
                observed.extend(addresses)
            if len(rows) < 200:
                break
        count = self.sink_counts(expected)
        if len(observed) != len(set(observed)) or set(observed) != expected or count != len(expected):
            raise QualificationFailure("SMTP sink, assignment scope and publish journal do not reconcile exactly")
        self.evidence.event(
            "sink_accounting_verified",
            expected=len(expected),
            actual_messages=len(observed),
            smtp_acceptances=count,
            recipient_delivery_confirmed=False,
        )
        return count

    def critical_probe(self, prefix: str) -> None:
        from kp_contracts.queue import JobQueue

        queue = JobQueue(self.endpoints["redis"] + "?socket_timeout=2&socket_connect_timeout=2")
        try:
            for role, topic in (("retention", "retention"), ("audit-anchor", "audit-anchor")):
                log = self.evidence.root / f"{prefix}-worker-{role}.log"
                before = log.read_text().count('"worker_job_completed"')
                started = time.monotonic()
                key = str(uuid.uuid4())
                queue.publish(topic, {"qualification": self.evidence.run_id}, idempotency_key=key)
                while True:
                    stats = queue.queue_stats(topic)
                    completed = log.read_text().count('"worker_job_completed"') > before
                    if role == "retention":
                        with self.engine.connect() as connection:
                            completed = completed and bool(
                                connection.scalar(
                                    text("SELECT count(*) FROM retention_actions WHERE idempotency_key=:key"),
                                    {"key": key},
                                )
                            )
                    if stats["dead_letter"]:
                        raise QualificationFailure(f"critical qualification job entered dead-letter queue: {role}")
                    if completed and not any(stats[field] for field in ("ready", "processing", "delayed")):
                        break
                    if time.monotonic() - started > self.evidence.profile.critical_seconds:
                        raise QualificationFailure(f"critical role progress exceeded target: {role}")
                    self.evidence.remaining()
                    time.sleep(0.02)
                elapsed = time.monotonic() - started
                if elapsed > self.evidence.profile.critical_seconds:
                    raise QualificationFailure(f"critical role progress exceeded target: {role}")
                self.evidence.event(
                    "critical_progress",
                    role=role,
                    seconds=elapsed,
                    observation="real_handler_completion_and_queue_drain",
                    idempotency_key=key,
                )
        finally:
            queue.close()

    def verify_normal_latency(self) -> None:
        p95 = percentile(self.latencies)
        self.evidence.json(
            "normal-api-latency.json",
            {"samples": len(self.latencies), "p95_seconds": p95, "maximum_seconds": max(self.latencies)},
        )
        if p95 > self.evidence.profile.api_p95_seconds:
            raise QualificationFailure("normal API latency target exceeded")

    def queue_observation(self, *, require_drained: bool = False) -> bool:
        from kp_contracts.queue import DEFAULT_QUEUE_TOPICS, JobQueue

        queue = JobQueue(self.endpoints["redis"] + "?socket_timeout=2&socket_connect_timeout=2")
        try:
            statistics = {topic: queue.queue_stats(topic) for topic in DEFAULT_QUEUE_TOPICS}
        finally:
            queue.close()
        with self.engine.connect() as connection:
            outbox = {
                str(status): int(count)
                for status, count in connection.execute(
                    text("SELECT status,count(*) FROM transactional_outbox GROUP BY status")
                ).all()
            }
        self.evidence.event("queue_outbox_observation", queues=statistics, outbox=outbox)
        if require_drained:
            if any(
                row["dead_letter"] or row["processing"] or row["ready"] or row["delayed"] for row in statistics.values()
            ):
                return False
            if any(count for status, count in outbox.items() if status != "dispatched"):
                return False
        return True

    def finish_queues(self) -> None:
        deadline = time.monotonic() + self.evidence.remaining(self.evidence.profile.drain_seconds)
        while time.monotonic() < deadline:
            if self.queue_observation(require_drained=True):
                return
            time.sleep(0.25)
        raise QualificationFailure("unresolved queue or outbox work after drain deadline")

    def exercise_training(self, campaign: dict[str, Any], *, allow_completed: bool = False) -> None:
        recipient = f"{campaign['label']}-0@qualification.test"
        selected = None
        for offset in range(0, 20000, 200):
            response = self.client.get(
                self.endpoints["mailpit"] + "/api/v1/messages", params={"start": offset, "limit": 200}
            )
            response.raise_for_status()
            rows = response.json()["messages"]
            for row in rows:
                if any(item.get("Address") == recipient for item in row.get("To", [])):
                    selected = row["ID"]
                    break
            if selected or len(rows) < 200:
                break
        if not selected or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", selected):
            raise QualificationFailure("SMTP sink message missing for training exercise")
        response = self.client.get(self.endpoints["mailpit"] + f"/api/v1/message/{selected}")
        response.raise_for_status()
        if len(response.content) > 1024 * 1024:
            raise QualificationFailure("sink message exceeded evidence bound")
        detail = response.json()
        rendered = html.unescape(str(detail.get("Text", "")) + str(detail.get("HTML", "")))
        tracking = self.endpoints["tracking"]
        click = re.search(re.escape(tracking) + r"/v1/track/click/[A-Za-z0-9_-]{40,128}", rendered)
        if not click:
            raise QualificationFailure("recipient-bound tracking link missing from actual message")
        response = self.client.get(click.group())
        if response.status_code != 302:
            raise QualificationFailure("actual tracking click did not redirect")
        from urllib.parse import urljoin

        location = urljoin(tracking, response.headers["location"])
        if not location.startswith(tracking + "/v1/training/"):
            raise QualificationFailure("training redirect escaped this run")
        page = self.client.get(location)
        if allow_completed and page.status_code == 200 and "Training complete" in page.text:
            self.evidence.event("restored_completed_training_link_verified", campaign_id=campaign["id"])
            return
        match = re.search(r'action="(/v1/training/[A-Za-z0-9_-]{40,128}/complete)"', page.text)
        if page.status_code != 200 or not match:
            raise QualificationFailure("recipient-bound training form unavailable")
        completed = self.client.post(tracking + match.group(1), data={"answer": "Verify independently"})
        if completed.status_code != 200 or "Training complete" not in completed.text:
            raise QualificationFailure("actual knowledge-check completion failed")
        replay = self.client.post(tracking + match.group(1))
        if replay.status_code != 200:
            raise QualificationFailure("completed training replay was not idempotent")
        self.evidence.event("tracking_training_completed", campaign_id=campaign["id"], message_id=selected)

    def soak(self, campaign: dict[str, Any], prefix: str) -> None:
        started = time.monotonic()
        duration = self.evidence.profile.soak_seconds
        first_fully_accepted = None
        samples = 0
        while time.monotonic() - started < duration:
            self.evidence.remaining()
            states = self.observe(campaign)
            accepted = sum(count for state, count in states.items() if state.lower() in {"accepted", "delivered"})
            if accepted == campaign["size"] and first_fully_accepted is None:
                first_fully_accepted = time.monotonic() - started
            self.request("GET", f"/campaigns/{campaign['id']}/report")
            self.queue_observation()
            self.critical_probe(prefix)
            samples += 1
            time.sleep(min(1, max(0, duration - (time.monotonic() - started))))
        self.evidence.json(
            "delivery-soak.json",
            {
                "campaign_id": campaign["id"],
                "recipient_count": campaign["size"],
                "seconds": duration,
                "samples": samples,
                "first_fully_accepted_seconds": first_fully_accepted,
                "delivery_pending_observation_seconds": first_fully_accepted
                if first_fully_accepted is not None
                else duration,
                "post_delivery_idle_observation_seconds": max(0, duration - first_fully_accepted)
                if first_fully_accepted is not None
                else 0,
                "constant_delivery_load_claimed": False,
            },
        )
