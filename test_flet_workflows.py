"""Regression checks for the two new behaviours in the Flet design."""

import unittest
from unittest.mock import Mock
from auto_download.worker import Agent
from flet_ui.transfers import TransferEvents
from pathlib import Path
import tempfile
from auto_download.worker import atomic_json
from auto_download.model import new_job
import hashlib
import io


class DownloadAndDelayTests(unittest.TestCase):
    def test_delay_applies_once_after_first_confirmed_hop_only(self):
        stop = Mock()
        stop.wait.return_value = False
        q = TransferEvents(5, stop)
        for completed, phase, total in [
            (0, "running", 2),
            (1, "done", 1),
            (1, "between_steps", 2),
            (1, "between_steps", 2),
            (2, "done", 2),
        ]:
            q.put(("progress", dict(completed=completed, phase=phase, total=total)))
        stop.wait.assert_called_once_with(5)

    def test_changed_old_file_is_ignored_and_one_new_file_is_saved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dest = root / "out"
            dest.mkdir()
            atomic_json(
                root / "config.json",
                dict(
                    new_job(),
                    cloud={
                        "name": "test",
                        "provider": "gdrive",
                        "access_token": "example",
                    },
                    filename="",
                    destination=str(dest),
                    interval=1,
                    new_files_only=True,
                    include_existing=False,
                ),
            )
            cloud = Mock(provider="gdrive")

            def entry(name, version):
                return dict(
                    id=name,
                    name=name,
                    version=version,
                    size=1,
                    md5=hashlib.md5(b"x").hexdigest(),
                    url="https://example.invalid/data",
                )

            old = entry("old.csv", "1")
            updated = entry("old.csv", "2")
            new = entry("new.csv", "1")
            polls = iter([[old], [updated], [updated, new]])
            cloud.items.side_effect = lambda: next(polls, [updated, new])
            cloud.open.return_value = io.BytesIO(b"x")
            job = Agent(root, cloud, clock=lambda: 10, sleeper=lambda seconds: None)
            job.run()
            self.assertEqual(job.state["status"], "done")
            self.assertEqual([p.name for p in dest.iterdir()], ["new.csv"])
            cloud.open.assert_called_once()
