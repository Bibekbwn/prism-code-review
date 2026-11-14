"""Language correctness of the generated fixes and of the measured metrics.

The autofix helpers were written for Python and then applied to every file:
`apiKey := "..."` in Go became `apiKey = os.getenv("APIKEY")`, which does not
compile, and a brace inside a Go block comment was counted as structure. These
tests pin the language-aware behaviour.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from prism.agents import Finding
from prism.agents_quality import MAX_FUNCTION_LENGTH, _cyclomatic_complexity, _count_lines_in_function
from prism.autofix import apply_fixes, generate_fix
from prism.langs import lang_for, strip_source

Q = '"'


def _secret_finding(file):
    return Finding(agent="security", severity="critical", category="Secret Exposure",
                   message="Possible api key detected", file=file, line=1,
                   rule_id="SECU-101")


def _eval_finding(file):
    return Finding(agent="security", severity="high", category="Code Injection",
                   message="Use of eval() detected", file=file, line=1,
                   rule_id="SECU-201")


class TestSecretFixPerLanguage:
    def test_go_uses_getenv_and_keeps_short_declaration(self):
        line = "\tapiKey := " + Q + "sk-live-abc" + Q
        fixed = generate_fix(_secret_finding("main.go"), line)
        assert fixed == "\tapiKey := os.Getenv(" + Q + "APIKEY" + Q + ")"

    def test_javascript_uses_process_env(self):
        line = "  const token = " + Q + "ghp_abc" + Q + ";"
        fixed = generate_fix(_secret_finding("app.js"), line)
        assert fixed == "  const token = process.env.TOKEN;"

    def test_java_keeps_the_declared_type(self):
        line = "    String apiKey = " + Q + "abc" + Q + ";"
        fixed = generate_fix(_secret_finding("App.java"), line)
        assert fixed == "    String apiKey = System.getenv(" + Q + "APIKEY" + Q + ");"

    def test_python_qualifier_is_preserved(self):
        line = "    self.password = " + Q + "hunter2" + Q
        fixed = generate_fix(_secret_finding("a.py"), line)
        assert fixed == "    self.password = os.getenv(" + Q + "PASSWORD" + Q + ")"

    def test_php_name_drops_the_sigil(self):
        line = "  $key = " + Q + "abc" + Q + ";"
        fixed = generate_fix(_secret_finding("a.php"), line)
        assert fixed == "  $key = getenv(" + Q + "KEY" + Q + ");"

    def test_equality_is_not_a_declaration(self):
        line = "  if (token == " + Q + "abc" + Q + ") {"
        assert generate_fix(_secret_finding("app.js"), line) == line

    def test_a_call_is_not_a_declaration(self):
        line = "  login(user, " + Q + "abc" + Q + ");"
        assert generate_fix(_secret_finding("app.js"), line) == line


class TestDangerousCallFixPerLanguage:
    def test_go_comments_with_slashes(self):
        fixed = generate_fix(_eval_finding("main.go"), "\teval(userInput)")
        assert fixed.startswith("\t// eval() removed")
        assert "pass" not in fixed

    def test_python_returns_an_inert_value(self):
        fixed = generate_fix(_eval_finding("a.py"), "    return eval(x)")
        assert fixed == "    return None  # eval() removed - security risk"

    def test_javascript_comment_keeps_the_line_valid(self):
        fixed = generate_fix(_eval_finding("app.js"), "  eval(payload);")
        assert fixed == "  // eval() removed - security risk: eval(payload);"


class TestGoImportIsEnsured:
    GO = 'package main\n\nimport "fmt"\n\nfunc main() {\n\tapiKey := "x"\n\tfmt.Println(apiKey)\n}\n'

    def _apply(self, content):
        f = Finding(agent="security", severity="critical", category="Secret Exposure",
                    message="Possible api key detected", file="main.go", line=6,
                    rule_id="SECU-101")
        return apply_fixes([(f, '\tapiKey := os.Getenv("APIKEY")')], content)

    def test_import_is_added_when_missing(self):
        fixed = self._apply(self.GO)
        assert 'import "os"' in fixed
        assert 'os.Getenv("APIKEY")' in fixed

    def test_import_is_not_duplicated_when_present(self):
        content = 'package main\n\nimport (\n\t"os"\n)\n\nfunc main() {\n\tapiKey := "x"\n}\n'
        fixed = self._apply(content)
        assert fixed.count('"os"') == 1

    def test_no_import_added_without_the_call(self):
        content = self.GO.replace('apiKey := "x"', 'apiKey := "x"')
        assert 'import "os"' not in apply_fixes(
            [(Finding(agent="security", severity="low", category="Style",
                      message="unrelated", file="main.go", line=6), '\tapiKey := "x"')],
            content)


class TestBlockCommentIsNotStructure:
    def test_go_function_length_ignores_commented_braces(self):
        spec = lang_for("main.go")
        body = "\n".join([
            "func big() {",
            "\t/* a comment that closes nothing",
            "\t   but contains { and }",
            "\t*/",
            "\tx := 1",
            "\t_ = x",
            "}",
        ])
        lines = strip_source(body.split("\n"), spec)
        assert _count_lines_in_function(lines, 0, spec) == 7

    def test_go_complexity_ignores_commented_branches(self):
        spec = lang_for("main.go")
        body = "\n".join([
            "func f() {",
            "\t// if a {",
            "\t/* while b {",
            "\t*/",
            "\treturn",
            "}",
        ])
        lines = strip_source(body.split("\n"), spec)
        assert _cyclomatic_complexity(lines, spec) == 1

    def test_python_string_is_not_structure(self):
        spec = lang_for("a.py")
        body = "\n".join([
            "def f():",
            '    """Doc with a brace { inside."""',
            "    return 1",
        ])
        lines = strip_source(body.split("\n"), spec)
        # The docstring line is blank, so it counts towards nothing: the length
        # metric measures logic, and a multi-line string is not logic.
        assert lines[1].strip() == ""
        assert _count_lines_in_function(lines, 0, spec) == 2
        assert _cyclomatic_complexity(lines, spec) == 1

    def test_long_go_function_is_still_reported(self):
        spec = lang_for("main.go")
        body = ["func big() {"]
        body += ["\tx := %d" % i for i in range(MAX_FUNCTION_LENGTH + 10)]
        body.append("}")
        lines = strip_source(body, spec)
        assert _count_lines_in_function(lines, 0, spec) > MAX_FUNCTION_LENGTH