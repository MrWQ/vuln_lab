from __future__ import annotations

import asyncio
import json
import unittest

import httpx

from vuln_kb.ai_providers import OpenAICompatibleProvider, ProviderFailure, endpoint_for, validate_provider_host


class ProviderAdapterTests(unittest.TestCase):
    def test_endpoint_and_model_host_policy_are_separate_from_source_allowlists(self) -> None:
        self.assertEqual(endpoint_for("https://model.example/v1/"), "https://model.example/v1/chat/completions")
        self.assertEqual(validate_provider_host("http://localhost:8001/v1", []), "localhost")
        self.assertEqual(validate_provider_host("https://model.example/v1", ["model.example"]), "model.example")
        with self.assertRaises(ProviderFailure) as denied:
            validate_provider_host("https://model.example/v1", [])
        self.assertEqual(denied.exception.category, "host_not_allowed")
        with self.assertRaises(ProviderFailure):
            endpoint_for("https://user:secret@model.example/v1")

    def test_probe_checks_json_object_and_does_not_echo_model_content(self) -> None:
        observed = {}

        def handler(request: httpx.Request) -> httpx.Response:
            observed["auth"] = request.headers.get("authorization")
            observed["payload"] = json.loads(request.content)
            return httpx.Response(200, json={"choices": [{"message": {"content": '{"capability_test":true}'}}],
                                             "usage": {"prompt_tokens": 9, "completion_tokens": 3}})

        provider = OpenAICompatibleProvider("http://127.0.0.1:8000/v1", "fixture-model", "secret-key",
                                           transport=httpx.MockTransport(handler))
        report = asyncio.run(provider.probe())
        self.assertEqual(report, {"model": "fixture-model", "response_format": "json_object",
                                  "usage": {"input": 9, "output": 3}})
        self.assertEqual(observed["auth"], "Bearer secret-key")
        self.assertEqual(observed["payload"]["response_format"], {"type": "json_object"})
        self.assertNotIn("secret-key", json.dumps(report))
        self.assertNotIn("capability_test", json.dumps(report))

    def test_probe_classifies_auth_model_timeout_and_json_mode_failures(self) -> None:
        cases = [
            (401, {"error": {"message": "bad key"}}, "authentication_failed"),
            (404, {"error": {"message": "model not found"}}, "model_not_found"),
            (404, {"error": {"message": "route not found"}}, "endpoint_not_found"),
            (400, {"error": {"message": "response_format json_object unsupported"}}, "json_mode_unsupported"),
        ]
        for status, body, expected in cases:
            with self.subTest(category=expected):
                transport = httpx.MockTransport(lambda _request, s=status, b=body: httpx.Response(s, json=b))
                provider = OpenAICompatibleProvider("http://localhost/v1", "model", "key", transport=transport)
                with self.assertRaises(ProviderFailure) as raised:
                    asyncio.run(provider.probe())
                self.assertEqual(raised.exception.category, expected)

        def timeout(_request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("sensitive transport details")

        provider = OpenAICompatibleProvider("http://localhost/v1", "model", "key",
                                            transport=httpx.MockTransport(timeout))
        with self.assertRaises(ProviderFailure) as raised:
            asyncio.run(provider.probe())
        self.assertEqual(raised.exception.category, "timeout")
        self.assertNotIn("sensitive transport", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
