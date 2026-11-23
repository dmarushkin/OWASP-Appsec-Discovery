"""Parallel model calls within a rule run (``scan_service._ask_chunk``, LLM_CONCURRENCY) and the rate-limited
backend: results come back in chunk order whatever order the calls finish in, a stop asks no new object but keeps
the answers in flight, the rate limit is taken before every call. No database."""

import threading
import time
from types import SimpleNamespace


def load_scan_service(scanner):
    scanner.setenv(LLM_CONCURRENCY="3")
    return scanner.load("services.scan_service")


def objects(n):
    return [SimpleNamespace(object_key=f"k{i}", name=f"obj{i}") for i in range(n)]


def test_ask_chunk_keeps_the_chunk_order_and_bounds_the_calls_in_flight(scanner, monkeypatch):
    scan = load_scan_service(scanner)
    in_flight, peak, lock = [0], [0], threading.Lock()

    def slow_verdicts(rule, objs, backend):
        obj = objs[0]
        with lock:
            in_flight[0] += 1
            peak[0] = max(peak[0], in_flight[0])
        time.sleep(0.05 if obj.object_key in ("k0", "k3") else 0.005)      # the first ones finish last
        with lock:
            in_flight[0] -= 1
        return [f"verdict-{obj.object_key}"]

    monkeypatch.setattr(scan, "llm_rule_object_verdicts", slow_verdicts)
    chunk = objects(7)
    asked, left = scan._ask_chunk("rule", chunk, None, 3, lambda: False)
    assert [o.object_key for o, _ in asked] == [o.object_key for o in chunk]       # chunk order, not finish order
    assert [r for _, r in asked] == [[f"verdict-k{i}"] for i in range(7)] and left == []
    assert 2 <= peak[0] <= 3                                                        # bounded by the concurrency

    # concurrency 1: the sequential path, same contract
    calls = []
    monkeypatch.setattr(scan, "llm_rule_object_verdicts", lambda rule, objs, backend: calls.append(objs[0].object_key) or ["v"])
    asked, left = scan._ask_chunk("rule", chunk[:3], None, 1, lambda: False)
    assert calls == ["k0", "k1", "k2"] and len(asked) == 3 and left == []


def test_ask_chunk_stops_after_the_calls_in_flight(scanner, monkeypatch):
    scan = load_scan_service(scanner)
    stop = threading.Event()
    answered = []

    def verdicts(rule, objs, backend):
        answered.append(objs[0].object_key)
        stop.set()                                   # SIGTERM while the first calls are in flight
        time.sleep(0.02)
        return [objs[0].object_key]

    monkeypatch.setattr(scan, "llm_rule_object_verdicts", verdicts)
    chunk = objects(10)
    asked, left = scan._ask_chunk("rule", chunk, None, 3, stop.is_set)
    # the calls already started finish and their answers are kept; nothing new is started
    assert 1 <= len(asked) <= 3 and len(asked) + len(left) == 10
    assert [o.object_key for o, _ in asked] == sorted(answered, key=lambda k: int(k[1:]))
    assert [o.object_key for o in left] == [f"k{i}" for i in range(len(asked), 10)]

    stop.clear()
    answered.clear()
    asked, left = scan._ask_chunk("rule", chunk[:4], None, 1, stop.is_set)         # sequential: one call then stop
    assert [o.object_key for o, _ in asked] == ["k0"] and [o.object_key for o in left] == ["k1", "k2", "k3"]


def test_rate_limited_backend_takes_a_token_per_call_and_gives_up_on_stop(scanner, monkeypatch):
    score = scanner.use_real("services.score_service")
    from discovery_common import jobs, llm_rate
    taken = []
    monkeypatch.setattr(llm_rate, "wait", lambda rate, n=1, name=None, stop=None, **kw: taken.append((rate, stop())) or not stop())
    inner = SimpleNamespace(model="m", complete=lambda system, user, json_schema=None: f"answer:{user}")
    backend = score.RateLimitedBackend(inner, 90)
    assert backend.model == "m" and backend.complete("s", "u", json_schema={}) == "answer:u"
    assert taken == [(90.0, False)]

    jobs.request_stop()
    try:
        import pytest
        with pytest.raises(score.LlmError, match="stopping"):
            backend.complete("s", "u")
    finally:
        jobs.stop_event().clear()

    # get_llm_backend wraps the OpenAI backend only when LLM_RATE_PER_MIN is set
    scanner.setenv(LLM_API_URL="http://llm.example/v1", LLM_RATE_PER_MIN="0")
    score._backend = None
    assert type(score.get_llm_backend()).__name__ == "OpenAICompatibleBackend"
    scanner.setenv(LLM_RATE_PER_MIN="30")
    score._backend = None
    wrapped = score.get_llm_backend()
    assert isinstance(wrapped, score.RateLimitedBackend) and wrapped.rate_per_min == 30
    score._backend = None
