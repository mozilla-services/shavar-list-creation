import unittest
from unittest.mock import patch, call, MagicMock
import json
from lists2webkit import main
from constants import WEBKIT_BLOCK_ALL, WEBKIT_BLOCK_COOKIES

class TestLists2WebKit(unittest.TestCase):

    def test_build_rule(self):
        from lists2webkit import build_rule

        resource = "example.com"
        action_type = "block"
        entities = {"example.com": {"properties": ["property1"]}}

        expected_rule = {
            "action": {"type": action_type},
            "trigger": {
                "url-filter": "^https?://([^/]+\\.)?example\\.com",
                "load-type": ["third-party"],
                "unless-domain": ["*property1"]
            }
        }

        rule = build_rule(resource, action_type, entities)
        self.assertEqual(rule, expected_rule)

        resource_no_entity = "test.com"
        expected_rule_no_entity = {
            "action": {"type": action_type},
            "trigger": {
                "url-filter": "^https?://([^/]+\\.)?test\\.com",
                "load-type": ["third-party"]
            }
        }

        rule_no_entity = build_rule(resource_no_entity, action_type, entities)
        self.assertEqual(rule_no_entity, expected_rule_no_entity)


if __name__ == "__main__":
    unittest.main()
