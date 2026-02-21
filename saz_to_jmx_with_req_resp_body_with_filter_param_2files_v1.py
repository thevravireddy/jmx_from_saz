import zipfile
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs
import re

def parse_request(file_content):
    lines = file_content.splitlines()
    if not lines:
        return None
    try:
        method, url, _ = lines[0].split()
    except ValueError:
        return None
    if method.upper() == "CONNECT":
        return None

    headers, body, in_body = {}, "", False
    for line in lines[1:]:
        if line.strip() == "":
            in_body = True
            continue
        if in_body:
            body += line + "\n"
        else:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
    return {"method": method, "url": url, "headers": headers, "body": body.strip()}

def parse_response(file_content):
    fields = {}

    # Hidden inputs (handle both attribute orders)
    for match in re.findall(
        r'(?:name="([^"]+)"\s+value="([^"]+)"|value="([^"]+)"\s+name="([^"]+)")',
        file_content
    ):
        # match is a tuple of 4 possible groups
        if match[0] and match[1]:
            # case: name="X" value="Y"
            fields[match[0]] = {"value": match[1], "type": "html"}
        elif match[3] and match[2]:
            # case: value="Y" name="X"
            fields[match[3]] = {"value": match[2], "type": "html"}

    # Generic inputs (non-hidden)
    for match in re.findall(r'name="([^"]+)" value="([^"]+)"', file_content):
        if match[0] not in fields:
            fields[match[0]] = {"value": match[1], "type": "html"}

    # Select options
    for select_match in re.findall(r'<select[^>]+name="([^"]+)".*?>(.*?)</select>', file_content, re.S):
        field_name, select_block = select_match
        fields[field_name] = {"value": None, "type": "select"}

    # JSON fields
    for match in re.findall(r'"([^"]+)":"([^"]+)"', file_content):
        fields[match[0]] = {"value": match[1], "type": "json"}

    # Cookies
    for match in re.findall(r'Set-Cookie:\s*([^=]+)=([^;]+)', file_content):
        fields[match[0]] = {"value": match[1], "type": "cookie"}

    return fields


def classify_parameters(requests1, requests2, responses):
    dynamic_params, static_params = {}, {}
    def collect_params(req):
        params = {}
        parsed = urlparse(req["url"])
        qs = parse_qs(parsed.query)
        for k, v in qs.items():
            params[k] = v[0]
        for pair in req["body"].split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = v
        return params

    params1 = [collect_params(r[1]) for r in requests1]
    params2 = [collect_params(r[1]) for r in requests2]

    all_keys = set().union(*params1).union(*params2)
    for key in all_keys:
        values1 = {p.get(key) for p in params1 if key in p}
        values2 = {p.get(key) for p in params2 if key in p}
        differs = values1 != values2

        found_in_response = False
        source_type = None
        for resp in responses.values():
            if key in resp:
                found_in_response = True
                source_type = resp[key]["type"]
                break

        if differs or found_in_response:
            dynamic_params[key] = {"differs": differs, "response": found_in_response, "source_type": source_type}
        else:
            static_params[key] = {"differs": False, "response": False}

    return dynamic_params, static_params

def extract_requests_and_responses(saz_file, filter_domains=None, exact_match=False):
    requests, responses, lookup = [], {}, {}
    with zipfile.ZipFile(saz_file, 'r') as z:
        for name in z.namelist():
            if name.startswith("raw/") and name.endswith("_c.txt"):
                content = z.read(name).decode("utf-8", errors="ignore")
                req = parse_request(content)
                if req:
                    parsed = urlparse(req["url"])
                    domain = parsed.hostname or ""
                    resp_name = name.replace("_c.txt", "_s.txt")
                    lookup[resp_name] = req["url"]

                    # Multiple domain filtering
                    if filter_domains:
                        if exact_match:
                            if domain not in filter_domains:
                                continue
                        else:
                            if not any(fd in domain for fd in filter_domains):
                                continue

                    requests.append((name, req))

            elif name.startswith("raw/") and name.endswith("_s.txt"):
                content = z.read(name).decode("utf-8", errors="ignore")
                responses[name] = parse_response(content)
    return requests, responses, lookup


def print_request_parameters_with_sources(requests, responses, request_lookup):
    print("All request parameters with correlation sources:")
    for name, req in requests:
        parsed = urlparse(req["url"])
        qs = parse_qs(parsed.query)
        body_params = {}
        for pair in req["body"].split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                body_params[k] = v

        query_str = "&".join([f"{k}={v[0]}" for k, v in qs.items()]) if qs else ""
        full_url = parsed.scheme + "://" + (parsed.netloc or "") + parsed.path
        if query_str:
            full_url += "?" + query_str

        print(f"\nRequest {name}:")
        print(f"  Method: {req['method']}")
        print(f"  URL: {full_url}")

        if not qs and not body_params:
            print("  No parameter present in this request URL or in request body")
        else:
            if qs:
                print("  Query Params:")
                for k, v in qs.items():
                    source = None
                    source_url = None
                    for resp_name, resp_fields in responses.items():
                        if k in resp_fields:
                            source = f"{resp_name} ({resp_fields[k]['type']})"
                            source_url = request_lookup.get(resp_name, "(unknown URL)")
                            break
                    if source:
                        print(f"    {k}={v[0]} ← from {source}, response URL={source_url}")
                    else:
                        print(f"    {k}={v[0]} (no response source)")
            if body_params:
                print("  Body Params:")
                for k, v in body_params.items():
                    source = None
                    source_url = None
                    for resp_name, resp_fields in responses.items():
                        if k in resp_fields:
                            source = f"{resp_name} ({resp_fields[k]['type']})"
                            source_url = request_lookup.get(resp_name, "(unknown URL)")
                            break
                    if source:
                        print(f"    {k}={v} ← from {source}, response URL={source_url}")
                    else:
                        print(f"    {k}={v} (no response source)")



def print_correlations(dynamic_params, responses):
    print("\nCorrelation mapping:")
    for key, meta in dynamic_params.items():
        source = None
        for resp_name, resp_fields in responses.items():
            if key in resp_fields:
                source = f"{resp_name} ({resp_fields[key]['type']})"
                break
        if source:
            print(f" {key} → found in response {source}")
        else:
            print(f" {key} → dynamic (differs across SAZ files, no direct response source)")

def build_sampler(parent_tree, name, req, dynamic_params, request_lookup, all_responses, seen_extractors):
    parsed = urlparse(req["url"])
    sampler = ET.SubElement(parent_tree, "HTTPSamplerProxy",
                            guiclass="HttpTestSampleGui", testclass="HTTPSamplerProxy",
                            testname="HTTP Request", enabled="true")

    # URL parts
    ET.SubElement(sampler, "stringProp", name="HTTPSampler.protocol").text = parsed.scheme or "http"
    ET.SubElement(sampler, "stringProp", name="HTTPSampler.domain").text = parsed.hostname or ""
    ET.SubElement(sampler, "stringProp", name="HTTPSampler.port").text = str(parsed.port) if parsed.port else ""
    ET.SubElement(sampler, "stringProp", name="HTTPSampler.path").text = parsed.path or "/"
    ET.SubElement(sampler, "stringProp", name="HTTPSampler.method").text = req["method"]

    # Arguments block
    args = ET.SubElement(sampler, "elementProp", name="HTTPsampler.Arguments",
                         elementType="Arguments", guiclass="HTTPArgumentsPanel",
                         testclass="Arguments", testname="User Defined Variables", enabled="true")
    coll = ET.SubElement(args, "collectionProp", name="Arguments.arguments")

    # Add query params
    for k, v in parse_qs(parsed.query).items():
        add_argument(coll, k, v[0], dynamic_params)

    # Add body params
    for pair in req["body"].split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            add_argument(coll, k, v, dynamic_params)

    sampler_hash_tree = ET.SubElement(parent_tree, "hashTree")

    # Header Manager
    header_manager = ET.SubElement(sampler_hash_tree, "HeaderManager",
                                   guiclass="HeaderPanel", testclass="HeaderManager",
                                   testname="Headers", enabled="true")
    coll_headers = ET.SubElement(header_manager, "collectionProp", name="HeaderManager.headers")
    for k, v in req["headers"].items():
        el = ET.SubElement(coll_headers, "elementProp", name=k, elementType="Header")
        ET.SubElement(el, "stringProp", name="Header.name").text = k
        ET.SubElement(el, "stringProp", name="Header.value").text = v
    ET.SubElement(sampler_hash_tree, "hashTree")

    # Attach extractors only if this response contains the field
    resp_name = name.replace("_c.txt", "_s.txt")
    resp_fields = all_responses.get(resp_name, {})

    for key, meta in dynamic_params.items():
        if key not in resp_fields:
            continue
        if key in seen_extractors:
            continue
        if meta.get("source_type") in ("html", "cookie"):
            regex_extractor = ET.SubElement(sampler_hash_tree, "RegexExtractor",
                                            guiclass="RegexExtractorGui", testclass="RegexExtractor",
                                            testname=f"Extract {key}", enabled="true")
            ET.SubElement(regex_extractor, "stringProp", name="RegexExtractor.refname").text = key
            # Regex matches BlazeDemo hidden input order: value="..." name="key"
            ET.SubElement(regex_extractor, "stringProp",
                          name="RegexExtractor.regex").text = f'<input[^>]+value="([^"]+)"[^>]+name="{key}"'
            ET.SubElement(regex_extractor, "stringProp", name="RegexExtractor.template").text = "$1$"
            ET.SubElement(regex_extractor, "stringProp", name="RegexExtractor.default").text = "NOT_FOUND"
            ET.SubElement(regex_extractor, "boolProp", name="RegexExtractor.useHeaders").text = "false"
            ET.SubElement(sampler_hash_tree, "hashTree")
            seen_extractors.add(key)


        elif meta.get("source_type") == "json":
            json_extractor = ET.SubElement(sampler_hash_tree, "JSONPostProcessor",
                                           guiclass="JSONPostProcessorGui", testclass="JSONPostProcessor",
                                           testname=f"Extract {key}", enabled="true")
            ET.SubElement(json_extractor, "stringProp", name="JSONPostProcessor.referenceNames").text = key
            ET.SubElement(json_extractor, "stringProp", name="JSONPostProcessor.jsonPathExprs").text = f'$.{key}'
            ET.SubElement(json_extractor, "stringProp", name="JSONPostProcessor.defaultValues").text = "NOT_FOUND"
            ET.SubElement(json_extractor, "boolProp", name="JSONPostProcessor.computeConcatenation").text = "false"
            ET.SubElement(sampler_hash_tree, "hashTree")
            seen_extractors.add(key)
        elif meta.get("source_type") == "select":
            regex_extractor = ET.SubElement(sampler_hash_tree, "RegexExtractor",
                                            guiclass="RegexExtractorGui", testclass="RegexExtractor",
                                            testname=f"Extract {key}", enabled="true")
            ET.SubElement(regex_extractor, "stringProp", name="RegexExtractor.refname").text = key
            # Scoped regex: capture first option inside the correct select
            ET.SubElement(regex_extractor, "stringProp", name="RegexExtractor.regex").text = (
                f'(?s)<select[^>]+name="{key}".*?>.*?<option[^>]+value="(.+?)"'
            )
            ET.SubElement(regex_extractor, "stringProp", name="RegexExtractor.template").text = "$1$"
            ET.SubElement(regex_extractor, "stringProp", name="RegexExtractor.default").text = "NOT_FOUND"
            ET.SubElement(regex_extractor, "boolProp", name="RegexExtractor.useHeaders").text = "false"
            ET.SubElement(sampler_hash_tree, "hashTree")
            seen_extractors.add(key)


def add_argument(coll, name, value, dynamic_params):
    el = ET.SubElement(coll, "elementProp", name=name, elementType="HTTPArgument")
    ET.SubElement(el, "stringProp", name="Argument.name").text = name
    if name in dynamic_params:
        ET.SubElement(el, "stringProp", name="Argument.value").text = "${%s}" % name
    else:
        ET.SubElement(el, "stringProp", name="Argument.value").text = value
    ET.SubElement(el, "stringProp", name="Argument.metadata").text = "="



def saz_to_jmx(saz_file1, saz_file2, jmx_file, filter_domain=None, exact_match=False):
    # Parse both SAZ files for comparison
    requests1, responses1, lookup1 = extract_requests_and_responses(saz_file1, filter_domain, exact_match)
    requests2, responses2, lookup2 = extract_requests_and_responses(saz_file2, filter_domain, exact_match)

    print("\n========== Request1 related ==================")
    print_request_parameters_with_sources(requests1, responses1, lookup1)
    print("\n========== Request2 related ==================")
    print_request_parameters_with_sources(requests2, responses2, lookup2)

    # Merge responses for correlation
    all_responses = {**responses1, **responses2}
    request_lookup = {**lookup1, **lookup2}

    # Classify params using both SAZs
    dynamic_params, static_params = classify_parameters(requests1, requests2, all_responses)

    print("====================Correlation =====================")
    print_correlations(dynamic_params, all_responses)

    # Build JMX using only the first SAZ’s requests
    testplan = ET.Element("jmeterTestPlan", version="1.2", properties="5.0", jmeter="5.6.2")
    root_hash_tree = ET.SubElement(testplan, "hashTree")

    tp = ET.SubElement(root_hash_tree, "TestPlan",
                       guiclass="TestPlanGui", testclass="TestPlan",
                       testname="Test Plan", enabled="true")
    tp_hash_tree = ET.SubElement(root_hash_tree, "hashTree")

    thread_group = ET.SubElement(tp_hash_tree, "ThreadGroup",
                                 guiclass="ThreadGroupGui", testclass="ThreadGroup",
                                 testname="Thread Group", enabled="true")
    loop_ctrl = ET.SubElement(thread_group, "elementProp",
                              name="ThreadGroup.main_controller",
                              elementType="LoopController", guiclass="LoopControlPanel",
                              testclass="LoopController", testname="Loop Controller",
                              enabled="true")
    ET.SubElement(loop_ctrl, "stringProp", name="LoopController.loops").text = "1"
    ET.SubElement(loop_ctrl, "boolProp", name="LoopController.continue_forever").text = "false"
    ET.SubElement(thread_group, "stringProp", name="ThreadGroup.num_threads").text = "1"
    ET.SubElement(thread_group, "stringProp", name="ThreadGroup.ramp_time").text = "1"

    tg_hash_tree = ET.SubElement(tp_hash_tree, "hashTree")

    seen_extractors = set()

    for name, req in requests1:
        build_sampler(tg_hash_tree, name, req, dynamic_params, request_lookup, all_responses, seen_extractors)

    tree = ET.ElementTree(testplan)
    tree.write(jmx_file, encoding="utf-8", xml_declaration=True)


import argparse
import sys

def read_domains(file_path):
    """Read domains from a text file, one per line."""
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert SAZ files to JMX with dynamic correlation.")
    parser.add_argument("saz_file1", help="Path to first SAZ file")
    parser.add_argument("saz_file2", help="Path to second SAZ file")
    parser.add_argument("jmx_file", help="Output JMX file path")
    parser.add_argument("domains_file", help="Text file containing domains (one per line)")
    parser.add_argument("--exact", action="store_true", help="Use exact domain match")

    args = parser.parse_args()

    # Read domains from file
    filter_domains = read_domains(args.domains_file)

    # Call main function
    saz_to_jmx(
        args.saz_file1,
        args.saz_file2,
        args.jmx_file,
        filter_domain=filter_domains,
        exact_match=args.exact
    )

