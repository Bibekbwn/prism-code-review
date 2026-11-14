"""Reporting, cache and inspection commands.

Extracted from cli_commands.py; behaviour unchanged.
"""

import json
import sys
from pathlib import Path

from prism.cli_config import load_config, load_deviation_policy, get_config_path
from prism.codebase_cache import get_changed_files, get_cache_stats, clear_cache
from prism.feedback import load_feedback, suppress_summary
from prism.reports import load_report, delete_report, clear_reports, get_report_summary

VALID_SEVERITIES = ("critical", "high", "medium", "low")


def _cmd_reports(args):
    print(get_report_summary())


def _cmd_report(args):
    report = load_report(args.id)
    if report:
        print(json.dumps(report, indent=2, default=str))
    else:
        print("Report not found: {}".format(args.id), file=sys.stderr)
        sys.exit(1)


def _cmd_delete_report(args):
    success = delete_report(args.id)
    if success:
        print("Report deleted: {}".format(args.id))
    else:
        print("Report not found: {}".format(args.id))


def _cmd_clear_reports(args):
    if not args.force:
        confirm = input("Delete ALL reports? (y/N): ").strip().lower()
        if confirm != "y":
            print("Cancelled.")
            return
    count = clear_reports()
    print("Deleted {} report(s).".format(count))


def build_dashboard(open_browser=False):
    """Generate the self-contained HTML dashboard with embedded report data.

    The dashboard HTML is written to .prism-reports/dashboard.html with the
    full report data (including per-finding details) inlined as JSON, so it
    renders correctly when opened via file:// (no fetch/CORS issues) and can
    be shared as a single file. The dashboard supports severity/agent filters,
    charts, and per-finding detail views.

    Returns the path to the generated file, or None when the template is
    missing. When ``open_browser`` is true the file is handed to the default
    browser (the file:// URL is printed either way).
    """
    import json as _json
    from prism.reports import load_index

    viewer = Path(__file__).parent / "dashboard.html"
    if not viewer.exists():
        print("Dashboard template not found at: {}".format(viewer))
        return None

    # Load index summaries + full findings for each report
    index = load_index()
    summaries = index.get("reports", [])
    full_reports = []
    for entry in summaries:
        report = load_report(entry["id"])
        if report:
            full_reports.append(report)
        else:
            # Fall back to the index summary (no findings detail)
            full_reports.append(entry)

    template = viewer.read_text()
    embedded = _json.dumps(full_reports)

    # The template carries a `/* PRISM_DASHBOARD_DATA */` placeholder. Swapping
    # it keeps the data next to loadReports(), so the page renders from the
    # embedded array instead of fetching (file:// blocks fetch via CORS).
    marker = "/* PRISM_DASHBOARD_DATA */"
    if marker in template:
        html = template.replace(
            marker, "const EMBEDDED_REPORTS = " + embedded + ";", 1)
    else:
        # Older templates: define the data and append the call at the end.
        html = template.replace(
            "</script>",
            "const EMBEDDED_REPORTS = " + embedded + ";\n"
            "</script>",
        )
        if "loadReports();" not in html:
            html = html.replace("</script>", "loadReports();\n</script>")

    out_path = Path(".prism-reports/dashboard.html")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)
    abs_path = str(out_path.resolve())
    url = "file:///{}".format(abs_path.replace("\\", "/"))
    print("Dashboard: {}".format(url))
    print("Reports embedded: {}".format(len(full_reports)))
    if not full_reports:
        print("No reports yet - run `prism check <file>` to generate one.")
    print("Open this in your browser to see the visual report timeline.")

    if open_browser:
        open_dashboard(url)
    return str(out_path)


def open_dashboard(url):
    """Open the dashboard URL in the default browser.

    Failure is non-fatal (headless CI, no browser installed): the URL was
    already printed, so the developer can open it manually.
    """
    try:
        import webbrowser
        return webbrowser.open(url)
    except Exception:
        return False


def _cmd_dashboard(args):
    """Generate the dashboard and open it in the browser.

    A missing template is a packaging failure, not an empty report: exit
    non-zero so a script running `prism dashboard` does not read it as success.
    """
    if not build_dashboard(open_browser=True):
        sys.exit(1)


def _cmd_stats(args):
    print(get_report_summary())


def _get_config_value(config, dotted):
    """Read a config value by dotted path, e.g. quality_gates.max_complexity."""
    node = config
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _set_config_value(config, dotted, value):
    """Write a config value by dotted path, creating intermediate objects."""
    parts = dotted.split(".")
    node = config
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            node[part] = nxt
        node = nxt
    node[parts[-1]] = value


def _validate_config_value(key, value):
    """Return an error message for a value that would silently change behaviour.

    ``block_on`` drives the quality gate. Written as a bare string it still
    loads, but the membership test becomes a substring test, so every commit
    passes while the config looks correct. Refuse the write instead.
    """
    if key == "block_on":
        if not isinstance(value, list):
            return 'block_on must be a list, e.g. ["critical", "high"]'
        unknown = [v for v in value
                   if not isinstance(v, str) or v.lower() not in VALID_SEVERITIES]
        if unknown:
            return "block_on has unknown severity value(s): {} (valid: {})".format(
                ", ".join(repr(v) for v in unknown), ", ".join(VALID_SEVERITIES))
    return None


def _cmd_config(args):
    config = load_config()
    if getattr(args, "set", None):
        key, value = args.set
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            pass
        problem = _validate_config_value(key, value)
        if problem:
            print("Invalid value for {}: {}".format(key, problem), file=sys.stderr)
            print("No changes written.", file=sys.stderr)
            sys.exit(1)
        _set_config_value(config, key, value)
        # Write back to the file we read from, not always prism.json.
        config_path = get_config_path()
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        print("Set {} = {} ({})".format(key, value, config_path))
    elif getattr(args, "get", None):
        print("{} = {}".format(args.get, _get_config_value(config, args.get)))
    else:
        print(json.dumps(config, indent=2))


def _cmd_policy(args):
    policy = load_deviation_policy()
    print(json.dumps(policy, indent=2))


def _cmd_feedback(args):
    fb = load_feedback()
    print(json.dumps(fb, indent=2))


def _cmd_suppressed(args):
    print(json.dumps(suppress_summary(), indent=2))


def _cmd_cache(args):
    if args.action == "stats":
        stats = get_cache_stats()
        print(json.dumps(stats, indent=2))
    elif args.action == "clear":
        clear_cache()
        print("Cache cleared.")
    elif args.action == "status":
        changed, unchanged, cache = get_changed_files()
        print("Changed files: {}".format(len(changed)))
        print("Unchanged files (cached): {}".format(len(unchanged)))
        if changed:
            print("\nChanged:")
            for f in changed[:10]:
                print("  {}".format(f))
            if len(changed) > 10:
                print("  ... and {} more".format(len(changed) - 10))
