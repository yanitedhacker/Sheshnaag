from __future__ import annotations

import os
import random

from locust import HttpUser, between, task


DEFAULT_LIMIT = int(os.getenv("LAB_PATCH_LIMIT", "10"))


class CveThreatRadarUser(HttpUser):
    wait_time = between(0.2, 1.2)

    @task(5)
    def dashboard(self):
        self.client.get("/api/dashboard")

    @task(4)
    def patch_priorities(self):
        delay_days = random.choice([0, 7, 14, 30])
        self.client.get("/api/patches/priorities", params={"limit": DEFAULT_LIMIT, "delay_days": delay_days})

    @task(3)
    def patch_decisions(self):
        delay_days = random.choice([0, 7, 14, 30])
        self.client.get("/api/patches/decisions", params={"delay_days": delay_days})

    @task(2)
    def risk_summary(self):
        self.client.get("/api/risk/summary")

    @task(2)
    def cve_search(self):
        self.client.get("/api/cves/", params={"page_size": 10, "keyword": "remote"})

