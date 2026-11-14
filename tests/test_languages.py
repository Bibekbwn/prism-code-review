"""Language coverage: the deterministic agents must work on any language.

Before the language descriptors existed, every check carried its own
``endswith(".py")`` gate: a Go or Rust file was read, then nothing
language-specific ran on it, so the report was silently empty. These tests pin
the per-language behaviour that replaced those gates.
"""

from prism.agents_quality import QualityAgent
from prism.agents_security import SecurityAgent
from prism.langs import LANGUAGES, lang_for, strip_literals


def _messages(findings):
    return [f.message for f in findings]


class TestLanguageLookup:
    def test_every_declared_extension_resolves(self):
        for spec in LANGUAGES:
            for ext in spec.extensions:
                assert lang_for("pkg/module" + ext).name == spec.name

    def test_unknown_file_is_not_source(self):
        assert lang_for("README.md") is None
        assert lang_for("Makefile") is None

    def test_comment_syntax_follows_the_language(self):
        for path in ("a.go", "a.py", "a.js", "a.rs"):
            spec = lang_for(path)
            marker = spec.line_comments[0]
            stripped = strip_literals("x = 1  %s debugger;" % marker, spec)
            assert "debugger" not in stripped
            assert "x = 1" in stripped

    def test_string_literal_is_blanked(self):
        assert "debugger" not in strip_literals('print("debugger;")', lang_for("a.py"))


class TestSecurityAnyLanguage:
    def test_go_env_lookup_is_not_a_hardcoded_secret(self):
        # `token = os.Getenv(name)` reads the secret from the environment; only
        # the Python/Node spelling of that lookup used to be allowlisted.
        assert _messages(SecurityAgent()._check("main.go", "token = os.Getenv(name)\n", "")) == []

    def test_javascript_env_lookup_is_not_a_hardcoded_secret(self):
        src = "const token = process.env.GITHUB_TOKEN;\n"
        assert _messages(SecurityAgent()._check("app.js", src, "")) == []

    def test_go_short_declaration_secret_is_found(self):
        src = 'apiKey := "aB3dEfGh1jKlMnOp"\n'
        assert any("api key" in m.lower() for m in
                   _messages(SecurityAgent()._check("main.go", src, "")))

    def test_c_preprocessor_secret_is_found(self):
        src = '#define API_KEY "aB3dEfGh1jKlMnOp"\n'
        assert any("preprocessor secret" in m.lower() for m in
                   _messages(SecurityAgent()._check("config.h", src, "")))

    def test_go_shell_exec_is_flagged(self):
        src = 'cmd := exec.Command("sh", "-c", userInput)\n'
        assert any("command injection" in m for m in
                   _messages(SecurityAgent()._check("main.go", src, "")))

    def test_java_runtime_exec_is_flagged(self):
        src = 'Runtime.getRuntime().exec("rm -rf /");\n'
        assert any("command injection" in m for m in
                   _messages(SecurityAgent()._check("Main.java", src, "")))

    def test_python_secret_still_found(self):
        src = 'api_key = "aB3dEfGh1jKlMnOp"\n'
        assert any("api key" in m.lower() for m in
                   _messages(SecurityAgent()._check("settings.py", src, "")))


class TestQualityAnyLanguage:
    def test_long_go_function_is_reported(self):
        body = ["\tx := %d" % i for i in range(200)]
        src = "\n".join(["func big() {"] + body + ["}"])
        findings = QualityAgent()._check("main.go", src, "")
        assert any(f.rule_id == "QUAL-102" for f in findings)

    def test_go_complexity_counts_decisions(self):
        lines = ["func branchy(n int) int {"]
        lines += ["\tif n > %d { return 1 }" % i for i in range(20)]
        lines += ["\treturn 0", "}"]
        findings = QualityAgent()._check("main.go", "\n".join(lines), "")
        assert any(f.rule_id == "QUAL-103" for f in findings)

    def test_go_function_ends_at_its_brace(self):
        src = "func small() {\n\tprintln(1)\n}\n\nfunc other() {\n\tprintln(2)\n}\n"
        findings = QualityAgent()._check("main.go", src, "")
        assert not any(f.rule_id == "QUAL-102" for f in findings)

    def test_commented_out_branch_is_not_counted(self):
        src = "func f() int {\n\t// if true {\n\treturn 0\n}\n"
        findings = QualityAgent()._check("main.go", src, "")
        assert not any(f.rule_id == "QUAL-103" for f in findings)

    def test_rust_function_is_detected(self):
        body = ["\tx%d += 1;" % i for i in range(200)]
        src = "\n".join(["fn big() {"] + body + ["}"])
        findings = QualityAgent()._check("main.rs", src, "")
        assert any(f.rule_id == "QUAL-102" for f in findings)

    def test_language_without_naming_convention_gets_no_naming_finding(self):
        src = "func some_camelCase_name() {\n\tprintln(1)\n}\n"
        findings = QualityAgent()._check("main.go", src, "")
        assert not any(f.rule_id == "QUAL-107" for f in findings)