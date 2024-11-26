import json
import os
from settings import config
from constants import (
    DNT_SECTIONS,
    PRE_DNT_SECTIONS,
    ENTITYLIST_SECTIONS,
    WEBKIT_LISTS_DIR,
    WEBKIT_BLOCK_ALL,
    WEBKIT_BLOCK_COOKIES
)
from utils import (
    get_blocked_domains,
    add_domain_to_list,
    load_json_from_url
)

def process_and_sort_domains(domains):
    """Sorts and adds domains to the list, returning successfully added domains."""
    added_domains = []
    previous_domain = None
    output = []
    for domain in sorted(domains):
        if add_domain_to_list(domain, domain, previous_domain, None, output):
            added_domains.append(domain)
            previous_domain = domain
    return added_domains

def get_tracker_lists(section):
    """Retrieves and processes tracker lists for a given section."""
    blocked_domains = get_blocked_domains(config, section)
    processed_domains = process_and_sort_domains(blocked_domains)
    print(f"Processing tracker list: {section}")
    return {section: processed_domains}

def get_entity_list(section):
    """Retrieves the entity whitelist for a given section."""
    entity_data = load_json_from_url(config, section, 'entity_url')
    list_name = config.get(section, 'output')
    print(f"Processing entity list: {list_name}")
    return {
        res: {"properties": details.get("properties", [])}
        for details in entity_data.get("entities", {}).values()
        for res in details.get("resources", [])
    }

def build_url_filter(resource):
    escaped_resource = resource.replace('.', '\\.')
    return f"^https?://([^/]+\\.)?{escaped_resource}"

def find_entity_for_resource(resource, entities):
    for key_resource, entity in entities.items():
        if key_resource in resource:
            return entity
    return None

def build_rule(resource, action_type, entities):
    url_filter = build_url_filter(resource)
    entity = entities.get(resource) or find_entity_for_resource(resource, entities)
    unless_domains = [f"*{domain}" for domain in entity["properties"]] if entity and isinstance(entity.get("properties"), list) else []
    return {
        "action": {"type": action_type},
        "trigger": {
            "url-filter": url_filter,
            "load-type": ["third-party"],
            **({"unless-domain": unless_domains} if unless_domains else {})
        },
    }

def generate_content_blocker_list(resources, action_type, entities):
    """Generates a list of content blocker rules for a category."""
    return [build_rule(resource, action_type, entities) for resource in resources]

def write_to_file(content, output_file):
    # NOTE: This function mimics the behavior of the Swift implementation.
    # We intentionally generate a compact JSON format using separators instead of pretty-printing 
    # with json.dumps(indent=2/4). The goal is to create files that are small yet still readable.
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        f.write("[\n")
        for i, rule in enumerate(content):
            f.write(json.dumps(rule, separators=(',', ':')))
            if i < len(content) - 1:
                f.write(",\n")
        f.write("\n]")

def generate_webkit_lists(domains, action_type, name, entities):
    """Generates and writes WebKit-compatible JSON lists."""
    rules = generate_content_blocker_list(domains, action_type, entities)
    output_file = f"{WEBKIT_LISTS_DIR}/disconnect-{action_type}-{name}.json"
    write_to_file(rules, output_file)

def main():
    tracker_lists = {}
    entities = {}
    # Process each section in the configuration
    for name in config.sections():
        section = config[name]
        ios_include_as = section.get('ios_include_as')
        if not ios_include_as:
            continue
        print(f"Processing section: {name}")
        
        if name in PRE_DNT_SECTIONS or name in DNT_SECTIONS:
            tracker_lists.update(get_tracker_lists(name))
        
        if name in ENTITYLIST_SECTIONS:
            entities = get_entity_list(name)

    for name, domains in tracker_lists.items():
        # Generate WebKit block-all lists for all
        # sections with `ios_include_as``
        ios_include_as = config[name].get('ios_include_as')
        generate_webkit_lists(domains, WEBKIT_BLOCK_ALL, ios_include_as, entities)

        # Optionally generate block-cookies WebKit lists for all
        # sections with `ios_block_cookies`
        if config[name].getboolean('ios_block_cookies', False):
            generate_webkit_lists(domains, WEBKIT_BLOCK_COOKIES, ios_include_as, entities)

    print("All content blocker rules have been generated successfully.")

if __name__ == "__main__":
    main()
