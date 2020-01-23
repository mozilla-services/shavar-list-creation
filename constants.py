PLUGIN_SECTIONS = (
    "plugin-blocklist",
    "plugin-blocklist-experiment",
    "flash-blocklist",
    "flash-exceptions",
    "flash-allow",
    "flash-allow-exceptions",
    "flash-subdoc",
    "flash-subdoc-exceptions",
    "flashinfobar-exceptions"
)
WHITELIST_SECTIONS = (
    "entity-whitelist",
    "entity-whitelist-testing",
    "staging-entity-whitelist",
    "fastblock1-whitelist",
    "fastblock2-whitelist",
    "google-whitelist"
)
PRE_DNT_SECTIONS = (
    "tracking-protection",
    "tracking-protection-testing",
    "tracking-protection-standard",
    "tracking-protection-full",
    "staging-tracking-protection-standard",
    "staging-tracking-protection-full",
    "fanboy-annoyance",
    "fanboy-social",
    "easylist",
    "easyprivacy",
    "adguard",
    "social-tracking-protection",
    "social-tracking-protection-facebook",
    "social-tracking-protection-twitter",
    "social-tracking-protection-linkedin",
    "social-tracking-protection-youtube",
)
PRE_DNT_CONTENT_SECTIONS = (
    "tracking-protection-full",
    "staging-tracking-protection-full"
)
DNT_SECTIONS = (
    "tracking-protection-base",
    "tracking-protection-baseeff",
    "tracking-protection-basew3c",
    "tracking-protection-content",
    "tracking-protection-contenteff",
    "tracking-protection-contentw3c",
    "tracking-protection-ads",
    "tracking-protection-analytics",
    "tracking-protection-social",
    "tracking-protection-base-fingerprinting",
    "tracking-protection-content-fingerprinting",
    "tracking-protection-base-cryptomining",
    "tracking-protection-content-cryptomining",
    "tracking-protection-test-multitag",
    "fastblock1",
    "fastblock2",
    "fastblock3"
)
DNT_CONTENT_SECTIONS = (
    "tracking-protection-content",
    "tracking-protection-contenteff",
    "tracking-protection-contentw3c"
)
DNT_BLANK_SECTIONS = (
    "tracking-protection-base",
    "tracking-protection-content",
)
DNT_EFF_SECTIONS = (
    "tracking-protection-baseeff",
    "tracking-protection-contenteff",
)
DNT_W3C_SECTIONS = (
    "tracking-protection-basew3c",
    "tracking-protection-contentw3c"
)
FASTBLOCK_SECTIONS = (
    "fastblock1",
    "fastblock1-whitelist",
    "fastblock2",
    "fastblock2-whitelist",
    "fastblock3"
)
LARGE_ENTITIES_SECTIONS = {
    "google-whitelist",
}
STANDARD_ENTITY_SECTION = 'entity-whitelist'


FINGERPRINTING_TAG = 'fingerprinting'
CRYPTOMINING_TAG = 'cryptominer'
SESSION_REPLAY_TAG = 'session-replay'
PERFORMANCE_TAG = 'performance'
ALL_TAGS = {
    FINGERPRINTING_TAG,
    CRYPTOMINING_TAG,
    SESSION_REPLAY_TAG,
    PERFORMANCE_TAG
}

TEST_DOMAIN_TEMPLATE = '%s.dummytracker.org'

DEFAULT_DISCONNECT_LIST_CATEGORIES = [
    'Advertising|Analytics|Social|Disconnect']
DEFAULT_DISCONNECT_LIST_TAGS = {}

LIST_TYPE_ENTITY = 'Entity'
LIST_TYPE_PLUGIN = 'Plugin'
LIST_TYPE_TRACKER = 'Tracker'

LARGE_ENTITIES = [
    'Google',
]

VER_LARGE_ENTITIES_SEPARATION_STARTED = 74
