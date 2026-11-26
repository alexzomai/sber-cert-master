import json
import multiprocessing
import os
import shutil
import stat
import tempfile
import time
import unittest

from sber_cert_master import cli, config, tls
from sber_cert_master.client import SberClient
from sber_cert_master.core import DAY, Manager, NeedsReauth
from sber_cert_master.notify import Notifier

from fake_sber import Bank, FakeSber, make_pki

TESTS_TMP = os.environ.get("SCM_TEST_TMP") or os.path.join(os.path.expanduser("~"), ".cache", "agent-tmp")


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class RecordingNotifier(Notifier):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.sent = []
        self.texts = []

    def _send(self, level, title, text):
        self.sent.append((level, title))
        self.texts.append(text)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.makedirs(TESTS_TMP, exist_ok=True)
        cls.pki_dir = tempfile.mkdtemp(prefix="scm-pki-", dir=TESTS_TMP)
        cls.pki = make_pki(cls.pki_dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.pki_dir, ignore_errors=True)

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="scm-test-", dir=TESTS_TMP)
        self.clock = Clock()
        self.bank = Bank(self.clock)
        self.server = FakeSber(self.pki, self.bank)
        self.cfg_path = os.path.join(self.tmp, "config.toml")
        with open(self.cfg_path, "w") as f:
            f.write(f"""
state_dir = "{self.tmp}/state"
publish_dir = "{self.tmp}/public"
[profiles.main]
client_id = "12345"
api_base = "{self.server.url}"
auth_base = "{self.server.url}"
redirect_uri = "https://example.ru/cb"
probe_interval_seconds = 0
""")
        self.cfg = config.load(self.cfg_path)
        os.makedirs(self.cfg.state_dir, mode=0o700)
        shutil.copy(self.pki["ca.pem"], os.path.join(self.cfg.state_dir, "ca-bundle.pem"))
        self.notifier = RecordingNotifier({}, self.cfg.state_dir)
        self.m = self.manager()

    def tearDown(self):
        self.server.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def manager(self):
        return Manager(self.cfg, self.cfg.profiles["main"], self.notifier, clock=self.clock)

    def material(self, name="client"):
        with open(self.pki[f"{name}.pem"], "rb") as f, open(self.pki[f"{name}.key"], "rb") as k:
            return tls.build_material(f.read(), b"", k.read())

    def bootstrap(self, secret_age_days=0, cert="client"):
        self.m.init("InitialSecret123", self.material(cert), self.clock() - secret_age_days * DAY)
        self.m.import_refresh_token(self.bank.issue_refresh_token())

    def state(self):
        with open(self.m.state_path) as f:
            return json.load(f)

    def published_token(self):
        with open(os.path.join(self.cfg.publish_dir, "main", "token.json")) as f:
            return json.load(f)


class TokenTests(Base):
    def test_bootstrap_publishes_token_and_tls(self):
        self.bootstrap()
        tok = self.published_token()
        self.assertIn(tok["access_token"], self.bank.access_tokens)
        pub = os.path.join(self.cfg.publish_dir, "main")
        for name in ("tls/client.crt", "tls/client.key", "tls/client.pem", "ca-bundle.pem", "env", "access_token"):
            self.assertTrue(os.path.exists(os.path.join(pub, name)), name)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(pub, "tls", "client.key")).st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(os.stat(self.m.state_path).st_mode), 0o600)
        env = dict(l.strip().split("=", 1) for l in open(os.path.join(pub, "env")))
        # env points into one immutable generation; the combined file is usable on its own
        self.assertEqual(os.path.dirname(env["SBER_CLIENT_CERT"]), os.path.dirname(env["SBER_CLIENT_KEY"]))
        import ssl
        ssl.create_default_context(cafile=env["SBER_CA_BUNDLE"]).load_cert_chain(env["SBER_CLIENT_PEM"])
        # refresh_token and client_secret are never published
        for root, _, files in os.walk(pub):
            for name in files:
                with open(os.path.join(root, name)) as f:
                    body = f.read()
                self.assertNotIn("InitialSecret123", body)
                self.assertNotIn(self.state()["refresh_token"], body)

    def test_proactive_refresh_before_expiry(self):
        self.bootstrap()
        first = self.published_token()["access_token"]
        self.m.tick()
        self.assertEqual(self.published_token()["access_token"], first, "no refresh while fresh")
        self.clock.advance(41 * 60)  # inside the 20 min margin
        self.m.tick()
        tok = self.published_token()
        self.assertNotEqual(tok["access_token"], first)
        self.assertGreater(tok["expires_at"] - self.clock(), 55 * 60)

    def test_lost_response_retries_same_refresh_token(self):
        self.bootstrap()
        rt_before = self.state()["refresh_token"]
        self.clock.advance(50 * 60)
        self.bank.faults = ["drop"]  # bank rotates the pair, but we never see the answer
        self.m.tick()
        self.assertEqual(self.state()["refresh_token"], rt_before)
        self.assertIn("refresh_failing_since", self.state())
        self.clock.advance(60)
        self.m.tick()  # the used token is a 2h reserve on the bank side -> works
        st = self.state()
        self.assertNotEqual(st["refresh_token"], rt_before)
        self.assertNotIn("refresh_failing_since", st)

    def test_incident_slow_bank_beyond_client_timeout(self):
        """Real incident: refresh took longer than the client timeout; the bank had already issued a new
        pair. The keeper must retry with the same refresh_token (2h reserve), not block the retry."""
        self.bootstrap()
        self.cfg.profiles["main"].http_timeout = 1.0
        rt0 = self.state()["refresh_token"]
        self.bank.token_delay = 1.5  # longer than the first timeout, shorter than the doubled one
        self.clock.advance(50 * 60)
        self.m.tick()  # times out; bank rotated rt0 -> reserve
        st = self.state()
        self.assertEqual(st["refresh_token"], rt0)
        self.assertEqual(st["refresh_transient_failures"], 1)
        self.assertEqual(self.bank.refresh_tokens[rt0]["status"], "reserve")
        self.clock.advance(60)
        self.m.tick()  # retry with rt0 (reserve) and a 2s timeout -> succeeds
        st = self.state()
        self.assertNotEqual(st["refresh_token"], rt0)
        self.assertNotIn("refresh_transient_failures", st)
        self.assertNotIn("refresh_failing_since", st)
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)
        self.assertFalse([t for l, t in self.notifier.sent if l == "critical"], self.notifier.sent)
        self.cfg.profiles["main"].http_timeout = 30.0
        self.bank.token_delay = 0

    def test_first_import_slow_bank_timeout_escalates(self):
        """No live grant yet; the bank answers slower than the base timeout: re-importing the same file
        must use a longer timeout and commit the pair on the second attempt."""
        self.m.init("InitialSecret123", self.material(), self.clock())
        self.cfg.profiles["main"].http_timeout = 1.0
        a = self.bank.issue_refresh_token()
        self.bank.token_delay = 1.5
        with self.assertRaises(Exception):
            self.m.import_refresh_token(a)
        self.assertEqual(self.m._refresh_timeout(self.state(), is_import=True), 2.0)
        self.m.import_refresh_token(a)  # 2 s budget > 1.5 s delay; uses the bank's reserve
        st = self.state()
        self.assertNotIn("import_refresh_token", st)
        self.assertIn(self.published_token()["access_token"], self.bank.access_tokens)
        self.bank.token_delay = 0
        self.cfg.profiles["main"].http_timeout = 30.0

    def test_incident_retry_after_reserve_window_alerts_reauth(self):
        """If retries could not succeed within the bank's 2h reserve window, say so loudly (not silently 401)."""
        self.bootstrap()
        self.bank.faults = ["drop"]
        self.clock.advance(50 * 60)
        self.m.tick()
        self.clock.advance(3 * 3600)  # e.g. host was down; the reserve has expired
        self.m.tick()
        self.assertTrue(any(l == "critical" and "повторная авторизация" in t for l, t in self.notifier.sent),
                        self.notifier.sent)

    def test_failed_early_refresh_is_retried_on_next_tick(self):
        """A forced/early refresh whose answer was lost: the bank revoked the old access token, so the
        keeper must retry at the next tick, not wait until its (now dead) token is due."""
        self.bootstrap()
        old_access = self.state()["access_token"]
        self.bank.faults = ["drop"]
        with self.assertRaises(Exception):
            self.m.ensure_fresh(force=True)  # e.g. the verification refresh after rotate-secret
        self.bank.access_tokens.pop(old_access, None)  # bank revoked it when issuing the lost pair
        self.clock.advance(60)
        self.m.tick()
        st = self.state()
        self.assertNotIn("refresh_failing_since", st)
        self.assertIn(st["access_token"], self.bank.access_tokens)

    def test_crash_during_early_refresh_is_recovered_after_restart(self):
        """kill -9 / reboot while the bank answers an early (forced) refresh: nothing was caught, but the
        in-flight marker is durable, so the restarted keeper retries at the first tick."""
        self.bootstrap()
        self.cfg.profiles["main"].probe_interval_seconds = 3600
        st = self.state()
        st["last_probe_at"] = self.clock()  # a recent probe: it will not rescue us
        with open(self.m.state_path, "w") as f:
            json.dump(st, f)
        real = SberClient.token_refresh

        def die_after_bank_applied(cl, *a, **k):
            real(cl, *a, **k)  # the bank issues a pair and revokes the published token...
            raise SystemExit("killed")  # ...and the process dies before handling the answer
        SberClient.token_refresh = die_after_bank_applied
        try:
            with self.assertRaises(SystemExit):
                self.m.ensure_fresh(force=True)
        finally:
            SberClient.token_refresh = real
        self.assertIn("refresh_ambiguous_since", self.state())
        m2 = self.manager()  # restart
        self.clock.advance(60)
        m2.tick()
        st = self.state()
        self.assertNotIn("refresh_ambiguous_since", st)
        self.assertIn(self.published_token()["access_token"], self.bank.access_tokens)
        self.cfg.profiles["main"].probe_interval_seconds = 0

    def test_rejection_after_lost_answer_keeps_ambiguity(self):
        """Lost answer (bank revoked our token), then 403 certificateNotFound on the retry, then the binding
        is repaired: the keeper must still refresh early, not wait for the normal margin."""
        self.bootstrap()
        self.cfg.profiles["main"].probe_interval_seconds = 3600
        st = self.state(); st["last_probe_at"] = self.clock()
        with open(self.m.state_path, "w") as f:
            json.dump(st, f)
        self.bank.faults = ["drop"]
        with self.assertRaises(Exception):
            self.m.ensure_fresh(force=True)
        self.bank.allowed_cert_serials = {"NONE"}  # 403 on the retry
        self.clock.advance(60)
        self.m.tick()
        self.assertIn("refresh_ambiguous_since", self.state())
        self.bank.allowed_cert_serials = None  # repaired
        self.clock.advance(11 * 60)  # past the rejection backoff
        self.m.tick()
        st = self.state()
        self.assertNotIn("refresh_ambiguous_since", st)
        self.assertIn(self.published_token()["access_token"], self.bank.access_tokens)
        self.cfg.profiles["main"].probe_interval_seconds = 0

    def test_rejected_import_keeps_live_grant_ambiguity(self):
        self.bootstrap()
        self.bank.faults = ["drop"]
        with self.assertRaises(Exception):
            self.m.ensure_fresh(force=True)
        with self.assertRaises(ValueError):
            self.m.import_refresh_token("0" * 38)  # definitively rejected candidate
        # the live grant's earlier ambiguity was not dropped by the candidate's rejection: it was
        # resolved by refreshing the live grant in the same pass
        st = self.state()
        self.assertNotIn("refresh_ambiguous_since", st)
        self.assertIn(self.published_token()["access_token"], self.bank.access_tokens)

    def test_legacy_state_transient_failure_is_treated_as_ambiguous(self):
        self.bootstrap()
        st = self.state()
        st["refresh_transient_failures"] = 1
        st["refresh_failing_since"] = self.clock()
        st["refresh_next_try_at"] = self.clock() + 600  # inherited rejection backoff must not delay it
        st.pop("refresh_ambiguous_since", None)
        with open(self.m.state_path, "w") as f:
            json.dump(st, f)
        before = self.bank.calls.get("/ic/sso/api/v2/oauth/token", 0)
        self.m.tick()
        self.assertEqual(self.bank.calls.get("/ic/sso/api/v2/oauth/token", 0), before + 1)
        self.assertNotIn("refresh_transient_failures", self.state())

    def test_staged_refresh_does_not_publish_before_activation(self):
        self.bootstrap()
        new = self.material("client2")
        self.clock.advance(50 * 60)  # staged refresh will be needed
        published = []
        orig = self.m._publish
        def spy(st):
            published.append(self.m.cert_status().serial)
            return orig(st)
        self.m._publish = spy
        self.m.install_cert(new)
        self.assertTrue(published)
        self.assertTrue(all(sn == new.info.serial for sn in published), published)

    def test_transient_after_rejection_is_retried_without_backoff(self):
        self.bootstrap()
        st = self.state()
        st["refresh_next_try_at"] = self.clock() + 600  # earlier definitive rejection backoff
        with open(self.m.state_path, "w") as f:
            json.dump(st, f)
        self.bank.faults = ["drop"]
        with self.assertRaises(Exception):
            self.m.ensure_fresh(force=True)
        self.assertNotIn("refresh_next_try_at", self.state())
        self.clock.advance(60)
        self.m.tick()
        self.assertIn(self.published_token()["access_token"], self.bank.access_tokens)

    def test_ambiguous_refresh_alerts_critical_early(self):
        self.bootstrap()
        self.bank.faults = ["drop"] * 10
        with self.assertRaises(Exception):
            self.m.ensure_fresh(force=True)
        for _ in range(7):
            self.clock.advance(60)
            self.m.tick()
        self.assertTrue(any(l == "critical" and "401" in t for l, t in self.notifier.sent), self.notifier.sent)

    def test_new_token_published_before_other_work(self):
        self.bootstrap()
        published = []
        orig = self.m._publish
        self.m._publish = lambda st: (published.append(st.get("access_token")), orig(st))[1]
        self.m.ensure_fresh(force=True)
        self.assertEqual(published[0], self.state()["access_token"])

    def test_refresh_timeout_escalates(self):
        self.bootstrap()
        st = self.state()
        self.assertEqual(self.m._refresh_timeout(st), 30.0)
        st["refresh_transient_failures"] = 2
        self.assertEqual(self.m._refresh_timeout(st), 120.0)
        st["refresh_transient_failures"] = 9
        self.assertEqual(self.m._refresh_timeout(st), 180.0)

    def test_5xx_is_retried(self):
        self.bootstrap()
        self.clock.advance(50 * 60)
        self.bank.faults = ["500", "500"]
        self.m.tick()
        self.m.tick()
        self.m.tick()
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)

    def test_invalid_refresh_token_alerts_reauth(self):
        self.bootstrap()
        self.bank.revoked = True
        self.clock.advance(50 * 60)
        self.m.tick()
        self.assertTrue(any("повторная авторизация" in t for _, t in self.notifier.sent), self.notifier.sent)
        with self.assertRaises(NeedsReauth):
            self.m.ensure_fresh(force=True)

    def test_rejected_import_keeps_working_token(self):
        self.bootstrap()
        good = self.state()["refresh_token"]
        for bad in ("", "   ", "0" * 38):
            with self.assertRaises(ValueError):
                self.m.import_refresh_token(bad)
            st = self.state()
            self.assertNotIn("import_refresh_token", st)
            # the live grant still works (it may have been refreshed in the same pass)
            self.assertTrue(st["refresh_token"] == good or st["refresh_token"] in self.bank.refresh_tokens)
            self.assertIn(self.published_token()["access_token"], self.bank.access_tokens)
        self.clock.advance(50 * 60)
        self.m.tick()
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)

    def test_import_with_lost_response_is_retried(self):
        self.bootstrap()
        new = self.bank.issue_refresh_token()
        self.bank.faults = ["drop"]
        with self.assertRaises(Exception):
            self.m.import_refresh_token(new)
        self.assertEqual(self.state()["import_refresh_token"]["value"], new)
        self.clock.advance(61)  # possibly consumed candidates are retried every minute
        self.m.tick()
        st = self.state()
        self.assertNotIn("import_refresh_token", st)
        self.assertNotIn("refresh_failing_since", st)

    def test_second_import_cannot_replace_unsettled_candidate(self):
        # fresh profile: no live refresh_token at all
        self.m.init("InitialSecret123", self.material(), self.clock())
        a, b = self.bank.issue_refresh_token(), "f" * 38
        self.bank.faults = ["drop"]  # bank consumed A, response lost
        with self.assertRaises(Exception):
            self.m.import_refresh_token(a)
        with self.assertRaises(ValueError):
            self.m.import_refresh_token(b)
        self.assertEqual(self.state()["import_refresh_token"]["value"], a)
        self.m.import_refresh_token(a)  # same value resumes the attempt (A is a reserve token now)
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)

    def test_malformed_success_reply_does_not_leak(self):
        from sber_cert_master import client as c
        self.assertEqual(c._error_code(b'{"error":"invalid_grant","error_description":"rt=SECRETVALUE"}'), "invalid_grant")
        self.assertEqual(c._error_code(b'{"error":"oops SECRETVALUE"}'), "")
        self.bootstrap()
        with self.assertRaises(c.Transient) as cm:
            self.m.client()._token_response(200, b'{"error":"x","error_description":"refresh_token=SECRETVALUE","access_token":"SECRETVALUE"}')
        self.assertNotIn("SECRETVALUE", str(cm.exception))

    def test_prod_error_shapes(self):
        """Error bodies exactly as returned by the production gateway (2026-11-26)."""
        from sber_cert_master import client as c
        self.assertEqual(c._error_code(b'{"errorCode":"certificateNotFound","errorMsg":"The certificate was not whitelisted for client_id=1"}'), "certificateNotFound")
        self.assertEqual(c._error_code(b'{"error":"invalid_client"}'), "invalid_client")
        self.assertEqual(c._error_code(b'{"error":"invalid_grant"}'), "invalid_grant")
        self.assertEqual(c._error_code(b'{"error":"invalid_token"}'), "invalid_token")
        self.assertEqual(c._error_code(b'{"cause":"UNAUTHORIZED"}'), "UNAUTHORIZED")
        e = c.Rejected(403, "certificateNotFound")
        self.assertIn("не привязан", str(e))
        self.assertNotIn("client_id=1", str(e))

    def test_bad_metadata_in_success_reply_is_neutralised(self):
        self.bootstrap()
        cl = self.m.client()
        tok = cl._token_response(200, json.dumps({"access_token": "a" * 38, "refresh_token": "b" * 38,
                                                  "expires_in": "SECRETVALUE", "scope": "x\nSECRETVALUE{}"}).encode())
        self.assertEqual(tok["expires_in"], 3600.0)
        self.assertIsNone(tok["scope"])
        st = self.state()
        self.m._store_tokens(st, tok)  # must not raise
        from sber_cert_master import client as c
        self.assertIsNone(c._number("SECRETVALUE", 1, 10))
        self.assertIsNone(c._number(True, 0, 10))
        self.assertEqual(c._number("40", 1, 3660), 40.0)

    def test_import_survives_non_grant_rejection(self):
        """Lost response, then a gateway 403 on the retry: the candidate must stay journaled."""
        self.m.init("InitialSecret123", self.material(), self.clock())
        a = self.bank.issue_refresh_token()
        self.bank.faults = ["drop"]
        with self.assertRaises(Exception):
            self.m.import_refresh_token(a)
        self.bank.allowed_cert_serials = {"NONE"}  # certificate binding still propagating -> 403
        with self.assertRaises(Exception):
            self.m.import_refresh_token(a)
        self.m.tick()
        self.assertEqual(self.state()["import_refresh_token"]["value"], a)
        self.bank.allowed_cert_serials = None
        self.clock.advance(601)
        self.m.tick()
        self.assertNotIn("import_refresh_token", self.state())
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)

    def test_import_candidate_survives_long_refusal_then_late_lost_response(self):
        """403 for almost 2h, then the bank consumes the token and the response is lost; retry must still work."""
        self.m.init("InitialSecret123", self.material(), self.clock())
        a = self.bank.issue_refresh_token()
        self.bank.allowed_cert_serials = {"NONE"}
        with self.assertRaises(Exception):
            self.m.import_refresh_token(a)
        self.clock.advance(115 * 60)
        self.bank.allowed_cert_serials = None
        self.bank.faults = ["drop"]  # consumed now, response lost
        with self.assertRaises(Exception):
            self.m.import_refresh_token(a)
        self.clock.advance(6 * 60)  # past the original staging deadline
        self.m.import_refresh_token(a)
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)

    def test_status_shows_resume_fields(self):
        self.m.init("InitialSecret123", self.material(), self.clock())
        st = self.m.status()
        self.assertIsNone(st["refresh_token_age_days"])
        self.assertFalse(st["import_pending"])
        self.bank.faults = ["drop"]
        with self.assertRaises(Exception):
            self.m.import_refresh_token(self.bank.issue_refresh_token())
        st = self.m.status()
        self.assertTrue(st["import_pending"])
        self.assertIsNone(st["refresh_token_age_days"])

    def test_staged_grant_survives_long_downtime_after_cert_rejection(self):
        """Only copy of the grant was imported, the bank answered 403 certificateNotFound, the keeper was
        stopped for >2h while the certificate got bound: the same candidate must still be tried."""
        self.m.init("InitialSecret123", self.material(), self.clock())
        a = self.bank.issue_refresh_token()
        self.bank.allowed_cert_serials = {"NONE"}
        with self.assertRaises(Exception):
            self.m.import_refresh_token(a)
        self.clock.advance(5 * 3600)
        self.bank.allowed_cert_serials = None
        m2 = self.manager()
        m2.tick()
        st = self.state()
        self.assertNotIn("import_refresh_token", st)
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)

    def test_rejected_candidate_does_not_block_live_grant(self):
        """Wrong file imported over a working keeper; the bank rejects the request (not the grant). The live
        grant must keep being refreshed past the bearer's expiry, and the candidate must stay journaled."""
        self.bootstrap()
        with self.assertRaises(Exception):
            self.m.import_refresh_token("X" * 4000)
        self.assertIn("rejected_at", self.state()["import_refresh_token"])
        for _ in range(4 * 12):  # 4 hours of 5-minute ticks, far past the bearer's expiry
            self.clock.advance(300)
            self.m.tick()
            self.assertGreater(self.published_token()["expires_at"], self.clock())
        st = self.state()
        self.assertIn("import_refresh_token", st)  # kept for repair, retried hourly, never applied
        self.assertIn(self.published_token()["access_token"], self.bank.access_tokens)

    def test_ambiguous_candidate_keeps_priority(self):
        self.bootstrap()
        cand = self.bank.issue_refresh_token()
        self.bank.faults = ["drop"]  # candidate consumed, answer lost
        with self.assertRaises(Exception):
            self.m.import_refresh_token(cand)
        self.assertTrue(self.state()["import_refresh_token"]["ambiguous_since"])
        # the import pass already re-synced the live grant, so agents have a valid bearer meanwhile
        self.assertIn(self.published_token()["access_token"], self.bank.access_tokens)
        self.clock.advance(61)
        self.m.tick()  # the possibly consumed candidate is retried (bank reserve) and adopted
        st = self.state()
        self.assertNotIn("import_refresh_token", st)
        self.assertIn(self.published_token()["access_token"], self.bank.access_tokens)

    def test_candidate_413_503_413_does_not_starve_live(self):
        """Round 20 scenario: oversized candidate (request rejected), one transient answer on an hourly
        retry, then rejected again: the live grant must keep the bearer valid throughout."""
        self.bootstrap()
        with self.assertRaises(Exception):
            self.m.import_refresh_token("X" * 4000)
        for hour in range(5):
            self.clock.advance(3600)
            if hour == 1:
                self.bank.faults = ["500"]
            for _ in range(8):
                self.clock.advance(15)
                self.m.tick()
            self.assertGreater(self.published_token()["expires_at"], self.clock())
            self.assertIn(self.published_token()["access_token"], self.bank.access_tokens)
        calls = self.bank.calls.get("/ic/sso/api/v2/oauth/token", 0)
        self.assertLess(calls, 40, "candidate retries are rate-limited")

    def test_ready_gate(self):
        self.cfg.profiles["main"].probe_interval_seconds = 3600
        self.bootstrap()
        self.assertEqual(self.m.readiness(), [])
        # lost answer: the bank revoked the published, locally unexpired bearer -> not ready
        self.bank.faults = ["drop"]
        with self.assertRaises(Exception):
            self.m.ensure_fresh(force=True)
        why = self.m.readiness()
        self.assertTrue(why)
        self.assertTrue(any("не завершено" in w for w in why), why)
        self.clock.advance(15)
        self.m.tick()
        self.assertEqual(self.m.readiness(), [])
        # bearer revoked behind our back (no marker): the probe catches it
        self.bank.access_tokens.clear()
        self.assertTrue(any("не принимает" in w for w in self.m.readiness()))
        self.assertTrue(any("осталось" in w for w in self.m.readiness(min_valid=10 ** 6, probe=False)))
        self.cfg.profiles["main"].probe_interval_seconds = 0

    def test_reinit_allowed_only_without_grant(self):
        self.m.init("InitialSecret123", self.material(), self.clock())
        self.m.init("NewSecret12345", self.material("client2"), self.clock())  # grantless: allowed
        self.assertEqual(self.state()["client_secret"], "NewSecret12345")
        self.bank.secrets = {"NewSecret12345": self.clock() + 40 * DAY}
        self.m.import_refresh_token(self.bank.issue_refresh_token())
        with self.assertRaises(FileExistsError):
            self.m.init("Other123456", self.material(), self.clock())
        self.m.init("Other123456", self.material(), self.clock(), overwrite=True)

    def test_set_secret_on_grantless_profile_and_with_journaled_import(self):
        self.m.init("OldSecret12345", self.material(), self.clock())
        self.m.set_secret("InitialSecret123")  # no grant: stored unverified, no exception
        self.assertEqual(self.state()["client_secret"], "InitialSecret123")
        # the legacy system rotated the secret to one this keeper has never seen
        self.bank.secrets = {"BrandNew12345": self.clock() + 40 * DAY}
        cand = self.bank.issue_refresh_token()
        with self.assertRaises(Exception):
            self.m.import_refresh_token(cand)  # 401 invalid_client, candidate kept
        self.assertIn("import_refresh_token", self.state())
        self.m.set_secret("BrandNew12345")  # verified through the journaled candidate
        st = self.state()
        self.assertNotIn("import_refresh_token", st)
        self.assertEqual(st["client_secret"], "BrandNew12345")
        self.assertIn(self.published_token()["access_token"], self.bank.access_tokens)

    def test_import_replace_flag(self):
        self.m.init("InitialSecret123", self.material(), self.clock())
        a, b = self.bank.issue_refresh_token(), self.bank.issue_refresh_token()
        self.bank.faults = ["500"]
        with self.assertRaises(Exception):
            self.m.import_refresh_token(a)
        with self.assertRaises(ValueError):
            self.m.import_refresh_token(b)
        self.m.import_refresh_token(b, replace=True)
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)

    def test_publish_group_requires_membership(self):
        import grp
        mine = {os.getegid(), *os.getgroups()}
        foreign = next((g for g in grp.getgrall() if g.gr_gid not in mine), None)
        if foreign is None or os.geteuid() == 0:
            self.skipTest("no foreign group")
        self.cfg.profiles["main"].publish_group = foreign.gr_name
        with self.assertRaises(ValueError):
            self.manager()
        self.cfg.profiles["main"].publish_group = None

    def test_republish_repairs_group_and_modes_of_existing_generation(self):
        self.bootstrap()
        pub = os.path.join(self.cfg.publish_dir, "main")
        gen = os.path.realpath(os.path.join(pub, "tls"))
        os.chmod(gen, 0o700)
        os.chmod(os.path.join(gen, "client.pem"), 0o600)
        self.m.tick()
        self.assertEqual(stat.S_IMODE(os.stat(gen).st_mode), 0o750)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(gen, "client.pem")).st_mode), 0o640)
        import grp
        others = [g for g in os.getgroups() if g != os.stat(gen).st_gid]
        if not others:
            self.skipTest("single group")
        self.cfg.profiles["main"].publish_group = grp.getgrgid(others[0]).gr_name
        m2 = self.manager()
        m2.tick()  # same TLS bytes, new publication group
        for path in (pub, gen, os.path.join(gen, "client.pem"), os.path.join(gen, "client.key"),
                     os.path.join(pub, "token.json"), os.path.join(pub, "env")):
            self.assertEqual(os.stat(path).st_gid, others[0], path)
        self.cfg.profiles["main"].publish_group = None

    def test_numeric_publish_group(self):
        self.cfg.profiles["main"].publish_group = str(os.getegid())
        m = self.manager()
        m.init("InitialSecret123", self.material(), self.clock())
        self.assertEqual(os.stat(os.path.join(self.cfg.publish_dir, "main", "env")).st_gid, os.getegid())
        self.cfg.profiles["main"].publish_group = None

    def test_init_publishes_tls_before_any_bank_call(self):
        self.m.init("InitialSecret123", self.material(), self.clock())
        self.assertTrue(os.path.exists(os.path.join(self.cfg.publish_dir, "main", "tls", "client.pem")))
        self.assertFalse(self.bank.calls)

    def test_duplicate_client_id_profiles_rejected(self):
        with open(self.cfg_path) as f:
            body = f.read()
        dup = os.path.join(self.tmp, "dup.toml")
        with open(dup, "w") as f:
            f.write(body + f'\n[profiles.second]\nclient_id = "12345"\napi_base = "{self.server.url.replace("127.0.0.1", "127.0.0.1.")}"\nauth_base = "{self.server.url}"\n')
        with self.assertRaises(config.ConfigError):
            config.load(dup)

    def test_errors_do_not_leak_credentials(self):
        self.bootstrap(secret_age_days=35)
        self.bank.echo_request_in_errors = True
        # a secret with a space: urlencode sends it as '+', which naive redaction would miss
        self.bank.secrets = {"Initial Secret 123": self.clock() + 5 * DAY}
        self.m.set_secret("Initial Secret 123", self.clock() - 35 * DAY)
        tok = self.state()["access_token"]
        self.bank.access_tokens[tok] = 0  # change-client-secret will be rejected with an echoing error
        self.m.tick()
        st = self.state()
        blob = json.dumps({k: st.get(k) for k in ("secret_rotation_error", "refresh_error", "probe_error")}, ensure_ascii=False)
        blob += json.dumps(self.notifier.texts, ensure_ascii=False)
        self.assertIn("secret_rotation_error", st)
        for secret in ("Initial Secret 123", "Initial+Secret+123", "Initial%20Secret", tok,
                       st["pending_client_secret"]["value"], st["refresh_token"]):
            self.assertNotIn(secret, blob)

    def test_redirect_is_not_followed(self):
        from sber_cert_master.client import Rejected
        self.bootstrap()
        self.bank.redirect_to = "http://127.0.0.1:9/steal"
        with self.assertRaises(Rejected) as cm:
            self.m.client().user_info(self.state()["access_token"])
        self.assertEqual(cm.exception.status, 302)

    def test_env_proxy_is_ignored_explicit_proxy_is_used(self):
        self.bootstrap()
        old = {k: os.environ.get(k) for k in ("HTTPS_PROXY", "https_proxy")}
        os.environ["HTTPS_PROXY"] = os.environ["https_proxy"] = "http://127.0.0.1:9"  # dead proxy
        try:
            self.m.ensure_fresh(force=True)  # must go direct and succeed
            self.cfg.profiles["main"].proxy = "http://127.0.0.1:9"
            from sber_cert_master.client import Transient
            with self.assertRaises(Transient):
                self.m.ensure_fresh(force=True)  # explicit proxy is honoured
        finally:
            self.cfg.profiles["main"].proxy = ""
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_proxy_config_contract(self):
        base = open(self.cfg_path).read()
        for bad in ("https://proxy:3128", "http://user:pw@proxy:3128", "socks5://proxy:1080", "http://proxy:3128/x"):
            p = os.path.join(self.tmp, "proxy.toml")
            with open(p, "w") as f:
                f.write(base.replace('probe_interval_seconds = 0', f'probe_interval_seconds = 0\nproxy = "{bad}"'))
            with self.assertRaises(config.ConfigError, msg=bad):
                config.load(p)

    def test_skill_python_example_does_not_follow_redirects(self):
        import re
        skill = open(os.path.join(os.path.dirname(__file__), "..", "docs", "agent-skill", "sber-api", "SKILL.md")).read()
        code = re.search(r"```python\n(.*?)```", skill, re.S).group(1)
        self.assertIn("NoRedirect()", code)
        self.assertIn("curl -q", skill)
        self.assertIn("--max-redirs 0", skill)

    def test_http_base_rejected(self):
        with open(self.cfg_path) as f:
            body = f.read().replace(self.server.url, self.server.url.replace("https://", "http://"))
        bad = os.path.join(self.tmp, "bad.toml")
        with open(bad, "w") as f:
            f.write(body)
        with self.assertRaises(config.ConfigError):
            config.load(bad)

    def test_exchange_code(self):
        self.m.init("InitialSecret123", self.material(), self.clock())
        url, state = self.m.auth_url()
        self.assertIn("code_challenge=", url)
        self.assertIn("client_id=12345", url)
        self.m.exchange_code("GOODCODE")
        self.assertIn(self.published_token()["access_token"], self.bank.access_tokens)

    def test_refresh_token_kept_alive_beyond_180_days(self):
        self.bootstrap()
        for _ in range(200):
            self.clock.advance(DAY)
            self.m.tick()
        self.assertGreater(self.published_token()["expires_at"], self.clock())


def _worker(cfg_path, n, out_q):
    cfg = config.load(cfg_path)
    m = Manager(cfg, cfg.profiles["main"], Notifier({}, cfg.state_dir))
    res = []
    for _ in range(n):
        st = m.ensure_fresh()
        res.append(st["access_token"])
    out_q.put(res)


class ConcurrencyTest(Base):
    def test_parallel_processes_do_not_race(self):
        # Real clock here: several processes compete for the lock.
        self.m.now = time.time
        self.bank.clock = time.time
        self.m.init("InitialSecret123", self.material(), time.time())
        st = self.state()
        st["refresh_token"] = self.bank.issue_refresh_token()
        with open(self.m.state_path, "w") as f:
            json.dump(st, f)
        q = multiprocessing.get_context("fork").Queue()
        procs = [multiprocessing.get_context("fork").Process(target=_worker, args=(self.cfg_path, 3, q)) for _ in range(8)]
        for p in procs:
            p.start()
        results = [q.get(timeout=60) for _ in procs]
        for p in procs:
            p.join(10)
        self.assertEqual(self.bank.calls.get("/ic/sso/api/v2/oauth/token"), 1, "exactly one refresh for 8 processes")
        self.assertEqual(len({t for r in results for t in r}), 1)


class SecretTests(Base):
    def test_rotation_when_due(self):
        self.bootstrap(secret_age_days=10)
        self.m.tick()
        self.assertEqual(self.state()["client_secret"], "InitialSecret123")
        self.clock.advance(21 * DAY)  # 31 days old
        self.m.tick()
        st = self.state()
        self.assertNotEqual(st["client_secret"], "InitialSecret123")
        self.assertTrue(self.bank.secret_ok(st["client_secret"]))
        self.assertAlmostEqual(st["client_secret_expires_at"] - self.clock(), 40 * DAY, delta=60)

    def test_secret_never_expires_over_a_year(self):
        self.bootstrap(secret_age_days=39, cert="client2")
        for _ in range(365 * 2):
            self.clock.advance(DAY / 2)
            self.m.tick()
        self.assertTrue(self.bank.secret_ok(self.state()["client_secret"]))
        self.assertGreater(self.published_token()["expires_at"], self.clock())
        self.assertFalse([s for s in self.notifier.sent if s[0] == "critical"], self.notifier.sent)

    def test_lost_change_response_is_settled(self):
        self.bootstrap(secret_age_days=35)
        self.bank.faults = ["drop"]  # bank applies the new secret, response lost
        self.m.tick()
        st = self.state()
        self.assertIn("pending_client_secret", st)
        self.assertEqual(st["client_secret"], "InitialSecret123")
        self.assertFalse(self.bank.secret_ok("InitialSecret123"))
        self.clock.advance(16 * 60)
        self.m.tick()  # refresh with the pending candidate settles it
        st = self.state()
        self.assertNotIn("pending_client_secret", st)
        self.assertTrue(self.bank.secret_ok(st["client_secret"]))

    def test_failed_change_keeps_candidate_until_settled_then_retries(self):
        self.bootstrap(secret_age_days=35)
        self.bank.faults = ["500"]  # bank did not apply
        self.m.tick()
        cand = self.state()["pending_client_secret"]["value"]
        calls = lambda: self.bank.calls.get("/ic/sso/api/v1/change-client-secret", 0)  # noqa: E731
        for _ in range(5 * 6):  # 5 hours: candidate is kept, no second change is stacked on it
            self.clock.advance(600)
            self.m.tick()
        st = self.state()
        self.assertEqual(st["pending_client_secret"]["value"], cand)
        self.assertEqual(st["client_secret"], "InitialSecret123")
        self.assertEqual(calls(), 1)
        for _ in range(2 * 6 + 1):  # past the settle window: dropped, rotation retried and succeeds
            self.clock.advance(600)
            self.m.tick()
        st = self.state()
        self.assertNotIn("pending_client_secret", st)
        self.assertNotEqual(st["client_secret"], "InitialSecret123")
        self.assertTrue(self.bank.secret_ok(st["client_secret"]))

    def test_change_applied_late_by_bank_is_recovered(self):
        """Timeout, old secret still works for a while, then the bank applies the change."""
        self.bootstrap(secret_age_days=35)
        self.bank.faults = ["late"]
        self.m.tick()
        cand = self.state()["pending_client_secret"]["value"]
        self.clock.advance(20 * 60)
        self.m.tick()  # candidate not applied yet, old secret works -> candidate must survive
        self.assertEqual(self.state()["pending_client_secret"]["value"], cand)
        self.bank.apply_deferred()
        self.assertFalse(self.bank.secret_ok("InitialSecret123"))
        self.clock.advance(20 * 60)
        self.m.tick()
        st = self.state()
        self.assertEqual(st["client_secret"], cand)
        self.assertNotIn("pending_client_secret", st)
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)

    def test_change_applied_after_candidate_dropped_recovers_from_history(self):
        self.bootstrap(secret_age_days=35)
        self.bank.faults = ["late"]
        self.m.tick()
        cand = self.state()["pending_client_secret"]["value"]
        st = self.state()
        st.pop("pending_client_secret")  # as if it had been discarded
        with open(self.m.state_path, "w") as f:
            json.dump(st, f)
        self.bank.apply_deferred()
        self.clock.advance(50 * 60)
        self.m.tick()
        self.assertEqual(self.state()["client_secret"], cand)

    def test_recovery_with_new_secret_and_new_code(self):
        """Old secret expired AND refresh_token revoked: set-secret + exchange-code must work."""
        self.bootstrap()
        self.bank.revoked = True
        self.bank.secrets = {"ChangedInLK123": self.clock() + 40 * DAY}
        with self.assertRaises(NeedsReauth):
            self.m.set_secret("ChangedInLK123")
        self.assertEqual(self.state()["pending_client_secret"]["value"], "ChangedInLK123")
        self.m.auth_url()
        self.m.exchange_code("GOODCODE")
        st = self.state()
        self.assertEqual(st["client_secret"], "ChangedInLK123")
        self.assertNotIn("pending_client_secret", st)
        self.bank.revoked = False
        self.clock.advance(50 * 60)
        self.m.tick()
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)

    def test_exchange_code_with_explicit_secret(self):
        self.bootstrap()
        self.bank.secrets = {"ChangedInLK123": self.clock() + 40 * DAY}
        self.m.exchange_code("GOODCODE", use_pkce=False, client_secret="ChangedInLK123")
        self.assertEqual(self.state()["client_secret"], "ChangedInLK123")

    def test_unknown_issue_date_rotates_immediately(self):
        self.m.init("InitialSecret123", self.material(), None)
        self.m.import_refresh_token(self.bank.issue_refresh_token())
        self.m.tick()
        self.assertNotEqual(self.state()["client_secret"], "InitialSecret123")

    def test_set_secret_validated_by_bank(self):
        self.bootstrap()
        with self.assertRaises(ValueError):
            self.m.set_secret("WrongSecret999")
        self.assertEqual(self.state()["client_secret"], "InitialSecret123")
        self.bank.secrets = {"ChangedInLK123": self.clock() + 40 * DAY}
        self.m.set_secret("ChangedInLK123")
        self.assertEqual(self.state()["client_secret"], "ChangedInLK123")


class TLSTests(Base):
    def test_init_from_p12(self):
        with open(self.pki["client.p12"], "rb") as f:
            mat = tls.load_p12(f.read(), "p12pass")
        self.assertIn("CI02745214-PROM-12345", mat.info.subject)
        self.m.init("InitialSecret123", mat, self.clock())
        self.m.import_refresh_token(self.bank.issue_refresh_token())

    def test_install_cert_switches_and_agents_see_it(self):
        self.bootstrap()
        self._env_before = dict(l.strip().split("=", 1) for l in open(os.path.join(self.cfg.publish_dir, "main", "env")))
        new = self.material("client2")
        self.m.install_cert(new)
        pub = os.path.join(self.cfg.publish_dir, "main")
        old_env = self._env_before
        env = dict(l.strip().split("=", 1) for l in open(os.path.join(pub, "env")))
        with open(env["SBER_CLIENT_CERT"], "rb") as f:
            self.assertEqual(tls.cert_info(tls.split_pem(f.read())[0]).serial, new.info.serial)
        self.assertNotEqual(env["SBER_CLIENT_CERT"], old_env["SBER_CLIENT_CERT"])
        # an agent that read env before the switch still has a complete, matching old pair
        tls.build_material(open(old_env["SBER_CLIENT_CERT"], "rb").read(), b"", open(old_env["SBER_CLIENT_KEY"], "rb").read())
        self.assertEqual(os.path.realpath(os.path.join(pub, "tls")), os.path.dirname(env["SBER_CLIENT_CERT"]))

    def test_install_cert_rejected_by_bank_keeps_old(self):
        self.bootstrap()
        old_serial = self.m.cert_status().serial
        # bank only whitelists the current cert (by decimal serial as python reports it)
        self.bank.allowed_cert_serials = {old_serial.upper()}
        with self.assertRaises(Exception):
            self.m.install_cert(self.material("client2"))
        self.assertEqual(self.m.cert_status().serial, old_serial)

    def test_crash_during_install_leaves_working_material(self):
        self.bootstrap()
        old_serial = self.m.cert_status().serial
        orig = self.m._activate_material
        self.m._activate_material = lambda gen: (_ for _ in ()).throw(KeyboardInterrupt())  # die right before the switch
        with self.assertRaises(KeyboardInterrupt):
            self.m.install_cert(self.material("client2"))
        self.m._activate_material = orig
        m2 = self.manager()  # "restart"
        self.assertEqual(m2.cert_status().serial, old_serial)
        self.clock.advance(50 * 60)
        m2.tick()
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)

    def test_install_cert_when_active_cert_is_dead(self):
        self.bootstrap()
        new = self.material("client2")
        # the bank no longer accepts the active cert, and the access token needs a refresh
        self.bank.allowed_cert_serials = {format(int(new.info.serial, 16), "X")}
        self.clock.advance(50 * 60)
        self.m.install_cert(new)
        self.assertEqual(self.m.cert_status().serial, new.info.serial)
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)

    def test_cert_and_grant_both_revoked_recovery(self):
        self.bootstrap()
        new = self.material("client2")
        self.bank.allowed_cert_serials = {format(int(new.info.serial, 16), "X")}
        self.bank.revoked = True
        self.clock.advance(50 * 60)
        with self.assertRaises(NeedsReauth):
            self.m.install_cert(new)
        self.assertEqual(self.m.cert_status().serial, new.info.serial)  # activated: mTLS proven
        self.m.exchange_code("GOODCODE", use_pkce=False)  # goes through the new cert
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)

    def test_legacy_published_paths_stay_current(self):
        self.bootstrap()
        pub = os.path.join(self.cfg.publish_dir, "main")
        for n in ("client.crt", "client.key"):  # as left behind by v0
            shutil.copy(os.path.join(pub, "tls", n), os.path.join(pub, n))
        new = self.material("client2")
        self.m.install_cert(new)
        with open(os.path.join(pub, "client.crt"), "rb") as c, open(os.path.join(pub, "client.key"), "rb") as k:
            self.assertEqual(tls.build_material(c.read(), b"", k.read()).info.serial, new.info.serial)

    def test_legacy_tls_layout_is_migrated(self):
        self.bootstrap()
        serial = self.m.cert_status().serial
        tdir = self.m.tls_dir
        real = os.path.realpath(os.path.join(tdir, "current"))
        shutil.copy(os.path.join(real, "client.crt"), os.path.join(tdir, "client.crt"))
        shutil.copy(os.path.join(real, "client.key"), os.path.join(tdir, "client.key"))
        os.unlink(os.path.join(tdir, "current"))
        shutil.rmtree(real)
        m2 = self.manager()
        self.clock.advance(50 * 60)
        m2.tick()
        self.assertEqual(m2.cert_status().serial, serial)
        self.assertFalse(os.path.exists(os.path.join(tdir, "client.key")))
        self.assertGreater(self.published_token()["expires_at"] - self.clock(), 50 * 60)

    def test_verify_ignores_system_trust(self):
        # a cert chaining only to a CA that is not in the given file must fail
        other = os.path.join(self.tmp, "other-ca.pem")
        with open(other, "wb") as f:
            f.write(tls.builtin_ca_bundle())
        with open(self.pki["client.pem"], "rb") as f, self.assertRaises(tls.TLSError):
            tls.verify_chain(f.read(), b"", other)

    def test_key_mismatch_rejected(self):
        with open(self.pki["client.pem"], "rb") as c, open(self.pki["client2.key"], "rb") as k:
            with self.assertRaises(tls.TLSError):
                tls.build_material(c.read(), b"", k.read())

    def test_expiry_alerts(self):
        self.m.init("InitialSecret123", self.material("client_short"), self.clock())
        self.m.import_refresh_token(self.bank.issue_refresh_token())
        self.m.tick()
        self.assertTrue(any(l == "critical" and "TLS-сертификат истекает" in t for l, t in self.notifier.sent),
                        self.notifier.sent)
        n = len(self.notifier.sent)
        self.clock.advance(601)  # past the TLS check interval: checked again, alert deduplicated
        self.m.tick()
        self.assertEqual(len(self.notifier.sent), n, "deduplicated")

    def test_tls_check_is_rate_limited(self):
        self.bootstrap()
        calls = []
        orig = self.m._check_tls
        self.m._check_tls = lambda: (calls.append(1), orig())[1]
        for _ in range(10):
            self.clock.advance(15)
            self.m.tick()
        self.assertEqual(len(calls), 1)
        self.clock.advance(600)
        self.m.tick()
        self.assertEqual(len(calls), 2)

    def test_csr_attributes(self):
        d = os.path.join(self.tmp, "csr")
        os.makedirs(d)
        subj = tls.make_csr("12345", "7700000000", "1027700000000", "Moscow", "Moscow",
                            os.path.join(d, "k"), os.path.join(d, "r")).decode()
        # RFC2253 prints in reverse order
        self.assertIn("C=RU,ST=Moscow,L=Moscow,OU=1027700000000,OU=CI02741778,OU=7700000000,OU=sbbapi-client-1y,OU=sm,CN=CI02745214-PROM-12345", subj)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(d, "k")).st_mode), 0o600)

    def test_builtin_bundle_pins(self):
        b = tls.builtin_ca_bundle()
        self.assertEqual(len(tls.split_pem(b)), 5)


class CLITests(Base):
    def test_preflight(self):
        import contextlib, io
        self.m.init("InitialSecret123", self.material(), self.clock())
        def run(*extra):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                rc = cli.main(["-c", self.cfg_path, "preflight", "main", *extra])
            return rc, out.getvalue()
        rc, out = run()
        self.assertEqual(rc, 0, out)
        self.bank.secrets = {"Other123456": self.clock() + 40 * DAY}
        rc, out = run()
        self.assertEqual(rc, 1); self.assertIn("client_secret", out)
        self.bank.allowed_cert_serials = {"NONE"}
        rc, out = run("--p12", self.pki["client.p12"], "--p12-password-file", self._pw_file())
        self.assertEqual(rc, 1); self.assertIn("не привязан", out)
        self.assertEqual(self.bank.refresh_tokens, {}, "no grant was issued or consumed")

    def _pw_file(self):
        p = os.path.join(self.tmp, "pw")
        with open(p, "w") as f:
            f.write("p12pass")
        return p

    def test_token_command_and_watchdog(self):
        self.bootstrap()
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(["-c", self.cfg_path, "token", "main", "--wait", "0"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue().strip(), self.published_token()["access_token"])
        with contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["token", "main", "--publish-dir", self.cfg.publish_dir, "--wait", "0", "--min-valid", "999999"])
        self.assertEqual(rc, 1)
        # watchdog: daemon never ticked -> problem
        self.assertTrue(self.manager().watchdog())


if __name__ == "__main__":
    unittest.main()


class TelemetryTests(Base):
    def all_secrets(self):
        st = self.state()
        vals = {st.get("client_secret"), st.get("refresh_token"), st.get("access_token")}
        vals |= {h["value"] for h in st.get("secret_history", [])}
        return {v for v in vals if v}

    def events_text(self):
        with open(os.path.join(self.m.dir, "events.jsonl")) as f:
            return f.read()

    def test_events_have_fingerprints_and_no_secrets(self):
        self.bootstrap(secret_age_days=35)
        self.bank.faults = ["drop"]
        self.clock.advance(50 * 60)
        self.m.tick()           # rotation + lost answer
        self.clock.advance(15)
        self.m.tick()
        text = self.events_text()
        kinds = [json.loads(l)["kind"] for l in text.splitlines()]
        for k in ("init", "import.begin", "refresh.decide", "refresh.try", "secret.rotate.begin", "publish"):
            self.assertIn(k, kinds)
        old_secret_and_tokens = self.all_secrets() | {"InitialSecret123"}
        for s in old_secret_and_tokens:
            self.assertNotIn(s, text)
        tries = [json.loads(l) for l in text.splitlines() if '"refresh.try"' in l]
        self.assertTrue(all(len(t["rt_fp"]) == 10 for t in tries))
        self.assertTrue(any(t["outcome"] == "transient" for t in tries) or any(
            json.loads(l).get("outcome") == "transient" for l in text.splitlines()))

    def test_health_json_published_without_secrets(self):
        self.bootstrap()
        self.m.tick()
        with open(os.path.join(self.cfg.publish_dir, "main", "health.json")) as f:
            h = json.load(f)
        self.assertEqual(h["access_token_fp"], __import__("sber_cert_master.telemetry", fromlist=["fp"]).fp(self.state()["access_token"]))
        self.assertTrue(h["recent_events"])
        blob = json.dumps(h)
        for s in self.all_secrets():
            self.assertNotIn(s, blob)

    def _diag(self, *extra):
        import contextlib, io
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(["-c", self.cfg_path, "diagnose", "main", "--json", *extra])
        return rc, json.loads(out.getvalue())

    def test_diagnose_healthy_and_no_secrets(self):
        self.m.now = time.time  # diagnose compares with the real clock
        self.bank.clock = time.time
        self.m.init("InitialSecret123", self.material(), time.time())
        self.bank.secrets = {"InitialSecret123": time.time() + 40 * DAY}
        self.m.import_refresh_token(self.bank.issue_refresh_token())
        self.m.tick()
        rc, out = self._diag()
        self.assertEqual(out["report"]["mode"], "keeper")
        self.assertEqual(out["report"]["preflight"]["result"], "ok")
        self.assertTrue(out["report"]["clock"]["ok"])
        self.assertEqual(rc, 0, out["findings"])
        blob = json.dumps(out)
        for s in self.all_secrets():
            self.assertNotIn(s, blob)

    def test_diagnose_explains_rejected_secret(self):
        self.m.now = time.time
        self.bank.clock = time.time
        self.m.init("InitialSecret123", self.material(), time.time())
        self.bank.secrets = {"InitialSecret123": time.time() + 40 * DAY}
        self.m.import_refresh_token(self.bank.issue_refresh_token())
        self.bank.secrets = {"ChangedElsewhere1": time.time() + 40 * DAY}  # someone rotated it in the LK
        with self.assertRaises(Exception):
            self.m.ensure_fresh(force=True)
        rc, out = self._diag()
        titles = " | ".join(f["title"] for f in out["findings"])
        self.assertEqual(rc, 2)
        self.assertIn("client_secret отклонён", titles)

    def test_diagnose_detects_second_refresher(self):
        self.m.now = time.time
        self.bank.clock = time.time
        self.cfg.profiles["main"].probe_interval_seconds = 1
        self.m.init("InitialSecret123", self.material(), time.time())
        self.bank.secrets = {"InitialSecret123": time.time() + 40 * DAY}
        self.m.import_refresh_token(self.bank.issue_refresh_token())
        # a legacy agent refreshes with our refresh_token behind our back -> our access token is revoked
        self.bank.refresh({"client_id": "12345", "client_secret": "InitialSecret123",
                           "refresh_token": self.state()["refresh_token"]})
        time.sleep(1.1)
        self.m.tick()  # probe -> 401 -> forced refresh (reserve) -> recovered
        rc, out = self._diag()
        titles = " | ".join(f["title"] for f in out["findings"])
        self.assertIn("второй", titles)
        self.cfg.profiles["main"].probe_interval_seconds = 0

    def test_diagnose_agent_mode(self):
        self.m.now = time.time
        self.bank.clock = time.time
        self.m.init("InitialSecret123", self.material(), time.time())
        self.bank.secrets = {"InitialSecret123": time.time() + 40 * DAY}
        self.m.import_refresh_token(self.bank.issue_refresh_token())
        self.m.tick()
        import contextlib, io
        def run():
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                rc = cli.main(["-c", "/nonexistent.toml", "diagnose", "main", "--json",
                               "--publish-dir", self.cfg.publish_dir])
            return rc, json.loads(out.getvalue())
        old_np = os.environ.get("NO_PROXY")
        os.environ["NO_PROXY"] = (old_np or "") + ",.sberbank.ru"
        self.addCleanup(lambda: os.environ.__setitem__("NO_PROXY", old_np) if old_np is not None else os.environ.pop("NO_PROXY", None))
        rc, out = run()
        self.assertEqual(out["report"]["mode"], "agent")
        self.assertEqual(out["report"]["probe"]["result"], "ok")
        self.assertEqual(rc, 0, out["findings"])
        self.assertNotIn(self.state()["access_token"], json.dumps(out))
        if os.geteuid() == 0:
            return  # root reads any file: the permission finding cannot be provoked
        os.chmod(os.path.join(self.cfg.publish_dir, "main", "token.json"), 0)
        try:
            rc, out = run()
            self.assertEqual(rc, 2)
            self.assertIn("нет прав", " | ".join(f["title"] for f in out["findings"]))
        finally:
            os.chmod(os.path.join(self.cfg.publish_dir, "main", "token.json"), 0o640)

    def test_event_journal_rotates(self):
        from sber_cert_master import telemetry
        old = telemetry.MAX_BYTES
        telemetry.MAX_BYTES = 2000
        try:
            self.bootstrap()
            for i in range(200):
                self.m.tel.event("x", i=i)
            self.assertTrue(os.path.exists(os.path.join(self.m.dir, "events.jsonl.1")))
            self.assertEqual(self.m.tel.tail(1)[0]["i"], 199)
        finally:
            telemetry.MAX_BYTES = old

    def test_diagnose_does_not_advise_reauth_for_old_import_rejection(self):
        """Round 28: import rejected (invalid_grant) -> live refresh ok -> live timeout. The advice must be
        'keep retrying', not 'get a new grant'."""
        self.m.now = time.time
        self.bank.clock = time.time
        self.m.init("InitialSecret123", self.material(), time.time())
        self.bank.secrets = {"InitialSecret123": time.time() + 40 * DAY}
        self.m.import_refresh_token(self.bank.issue_refresh_token())
        with self.assertRaises(ValueError):
            self.m.import_refresh_token("0" * 38)  # stale import: invalid_grant, live grant refreshed
        self.bank.faults = ["drop"]
        with self.assertRaises(Exception):
            self.m.ensure_fresh(force=True)  # live: lost answer
        rc, out = self._diag("--no-network")
        titles = " | ".join(f["title"] for f in out["findings"])
        self.assertNotIn("refresh_token недействителен", titles)
        self.assertIn("временные ошибки обновления", titles)

    def test_legacy_error_text_never_reaches_health_or_report(self):
        """Round 28: an older version stored bank answers that could echo credentials."""
        self.m.now = time.time
        self.bank.clock = time.time
        self.m.init("InitialSecret123", self.material(), time.time())
        self.bank.secrets = {"InitialSecret123": time.time() + 40 * DAY}
        self.m.import_refresh_token(self.bank.issue_refresh_token())
        st = self.state()
        leak = "client_secret=InitialSecret123&refresh_token=" + st["refresh_token"]
        st["refresh_error"] = st["secret_rotation_error"] = st["probe_error"] = "HTTP 400: " + leak
        st["refresh_failing_since"] = time.time()
        with open(self.m.state_path, "w") as f:
            json.dump(st, f)
        self.manager().tick()
        with open(os.path.join(self.cfg.publish_dir, "main", "health.json")) as f:
            health = f.read()
        rc, out = self._diag("--no-network")
        for blob in (health, json.dumps(out)):
            self.assertNotIn("InitialSecret123", blob)
            self.assertNotIn(st["refresh_token"], blob)

    def test_legacy_error_text_never_reaches_alerts(self):
        """Round 29: version<3 state with a stored bank echo, rotation in backoff -> expiry alert."""
        self.m.init("InitialSecret123", self.material(), self.clock() - 37 * DAY)
        self.m.import_refresh_token(self.bank.issue_refresh_token())
        st = self.state()
        echo = "HTTP 403: bad request client_secret=InitialSecret123 new=" + "A1" * 19
        st["secret_rotation_error"] = echo
        st["secret_next_try_at"] = self.clock() + 3000
        st["client_secret_expires_at"] = self.clock() + 2 * DAY
        st["version"] = 2
        with open(self.m.state_path, "w") as f:
            json.dump(st, f)
        self.notifier.sent.clear(); self.notifier.texts.clear()
        m2 = self.manager()
        m2.tick()
        blob = json.dumps([self.notifier.sent, self.notifier.texts], ensure_ascii=False)
        self.assertIn("client_secret", blob)  # the expiry alert was sent...
        self.assertNotIn("InitialSecret123", blob)  # ...without the echoed secret
        self.assertNotIn("A1" * 19, blob)
        self.assertEqual(self.state()["version"], 3)
