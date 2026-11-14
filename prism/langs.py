"""What the analyzers need to know about the language of a file.

Each check used to carry its own ``endswith(".py")`` gate, so a Go or Rust file
was read but nothing language-specific ran on it. The gates now ask for a
descriptor: adding a language is one entry in ``LANGUAGES`` rather than an edit
in every agent.
"""

import re
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class LanguageSpec:
    """The syntax facts a language-agnostic check needs.

    ``func_decl`` and ``class_decl`` match at the start of a line.
    ``body_style`` is ``"indent"`` (Python, Ruby) or ``"brace"`` (C family), and
    decides where a function ends. ``decision_words`` are counted at the start of
    a statement and ``logical_ops`` anywhere in it, which is how cyclomatic
    complexity is approximated. ``naming`` is the convention the naming rule
    enforces, or ``None`` for no check. ``env_lookup`` matches a read of a
    secret from the environment, which is a lookup rather than a hardcoded value.
    """

    name: str
    extensions: Tuple[str, ...]
    line_comments: Tuple[str, ...] = ("#",)
    strings: Tuple[str, ...] = ('"', "'")
    assign: str = r"\s*[:=]\s*"
    func_decl: Optional[re.Pattern] = None
    class_decl: Optional[re.Pattern] = None
    body_style: str = "indent"
    decision_words: Tuple[str, ...] = ()
    logical_ops: Tuple[str, ...] = ()
    naming: Optional[str] = None
    env_lookup: Tuple[str, ...] = ()


def _brace(name, extensions, func_decl, decision_words, **kwargs):
    """A C-family language: ``//`` comments, ``&&``/``||``, brace-delimited bodies."""
    return LanguageSpec(
        name=name, extensions=extensions, line_comments=("//",),
        strings=('"', "'"), func_decl=func_decl, body_style="brace",
        decision_words=decision_words, logical_ops=("&&", "||"), **kwargs)


# Java/C# style method head: optional modifiers, a return type, a name, a
# parameter list and an opening brace. The trailing ``{`` is what keeps ``if (x) {``
# and prototypes ending in ``;`` from being read as functions.
_JVM_METHOD = (r"^\s*(?:(?:public|private|protected|static|final|abstract|"
               r"synchronized|native|default|strictfp|override|virtual|async)\s+)*"
               r"[\w<>\[\],.?:]+\s+\w+\s*\([^;{}]*\)\s*(?:throws [\w.,\s]+)?\{")

LANGUAGES = [
    LanguageSpec(
        name="python", extensions=(".py", ".pyi"),
        line_comments=("#",), strings=('"', "'"),
        func_decl=re.compile(r"^\s*(?:async\s+)?def\s+\w+"),
        class_decl=re.compile(r"^\s*class\s+\w+"),
        body_style="indent",
        decision_words=("if", "elif", "for", "while", "except", "with", "case"),
        logical_ops=("and", "or"), naming="snake",
        env_lookup=(r"\bos\.getenv\b", r"\bos\.environ\b")),
    LanguageSpec(
        name="javascript", extensions=(".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"),
        line_comments=("//",), strings=('"', "'", "`"),
        func_decl=re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?"
                             r"function\s*\*?\s*\w+"
                             r"|^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*"
                             r"(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>"),
        class_decl=re.compile(r"^\s*(?:export\s+)?(?:default\s+)?class\s+\w+"),
        body_style="brace",
        decision_words=("if", "for", "while", "case", "catch"),
        logical_ops=("&&", "||"), naming="camel",
        env_lookup=(r"\bprocess\.env\b", r"\bimport\.meta\.env\b")),
    LanguageSpec(
        name="go", extensions=(".go",), line_comments=("//",), strings=('"', "`"),
        assign=r"\s*(?::=|=)\s*",
        func_decl=re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?\w+"),
        class_decl=re.compile(r"^\s*type\s+\w+\s+struct\b"),
        body_style="brace", decision_words=("if", "for", "case", "select"),
        logical_ops=("&&", "||"), env_lookup=(r"\bos\.Getenv\b",)),
    LanguageSpec(
        name="rust", extensions=(".rs",), line_comments=("//",), strings=('"',),
        func_decl=re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?"
                             r"(?:unsafe\s+)?(?:const\s+)?"
                             r"(?:extern\s+\"[^\"]*\"\s+)?fn\s+\w+"),
        class_decl=re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait)\s+\w+"),
        body_style="brace", decision_words=("if", "for", "while", "match", "loop"),
        logical_ops=("&&", "||"), env_lookup=(r"\benv::var\b",)),
    _brace("java", (".java",), re.compile(_JVM_METHOD),
           ("if", "for", "while", "case", "catch"),
           class_decl=re.compile(r"^\s*(?:public\s+)?(?:final\s+)?(?:class|interface|enum)\s+\w+"),
           env_lookup=(r"\bSystem\.getenv\b",)),
    _brace("csharp", (".cs",), re.compile(_JVM_METHOD),
           ("if", "for", "while", "case", "catch"),
           class_decl=re.compile(r"^\s*(?:public\s+)?(?:class|interface|struct|record)\s+\w+"),
           env_lookup=(r"\bEnvironment\.GetEnvironmentVariable\b",)),
    _brace("c", (".c", ".h"), re.compile(_JVM_METHOD),
           ("if", "for", "while", "case"),
           class_decl=re.compile(r"^\s*(?:struct|enum|union)\s+\w+"),
           env_lookup=(r"\bgetenv\s*\(",)),
    _brace("cpp", (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"),
           re.compile(_JVM_METHOD.replace(r"\s*\{", r"\s*(?:const\s*)?\{")),
           ("if", "for", "while", "case", "catch"),
           class_decl=re.compile(r"^\s*(?:class|struct|enum)\s+\w+"),
           env_lookup=(r"\bgetenv\s*\(",)),
    LanguageSpec(
        name="ruby", extensions=(".rb", ".rake"), line_comments=("#",),
        strings=('"', "'"), assign=r"\s*=\s*",
        func_decl=re.compile(r"^\s*def\s+\w+"),
        class_decl=re.compile(r"^\s*class\s+\w+"),
        body_style="indent",
        decision_words=("if", "elsif", "unless", "while", "until", "for", "when", "rescue"),
        logical_ops=("and", "or"), env_lookup=(r"\bENV\s*\[",)),
    _brace("php", (".php",), re.compile(
        r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*"
        r"function\s+\w+"),
        ("if", "for", "while", "case", "catch"),
        class_decl=re.compile(r"^\s*(?:(?:abstract|final)\s+)?class\s+\w+"),
        env_lookup=(r"\bgetenv\s*\(",)),
    _brace("kotlin", (".kt", ".kts"), re.compile(
        r"^\s*(?:(?:public|private|protected|internal|open|override|suspend|inline|"
        r"operator|data|abstract)\s+)*fun\s+(?:<[^>]*>\s*)?\w+"),
        ("if", "for", "while", "when", "catch"),
        class_decl=re.compile(r"^\s*(?:(?:public|private|internal|open|data|abstract|sealed)\s+)*"
                              r"(?:class|interface|object)\s+\w+"),
        env_lookup=(r"\bSystem\.getenv\b",)),
    _brace("swift", (".swift",), re.compile(
        r"^\s*(?:(?:public|private|internal|fileprivate|open|static|class|override|"
        r"mutating|nonmutating|convenience|required)\s+)*func\s+\w+"),
        ("if", "for", "while", "case", "guard"),
        class_decl=re.compile(r"^\s*(?:(?:public|private|internal|open|final)\s+)*"
                              r"(?:class|struct|enum|protocol|extension)\s+\w+"),
        env_lookup=(r"\bProcessInfo\.processInfo\.environment\b",)),
]

_BY_EXT = {ext: spec for spec in LANGUAGES for ext in spec.extensions}


def lang_for(path) -> Optional[LanguageSpec]:
    """The descriptor for ``path``, or ``None`` when it is not source code."""
    lowered = str(path).lower()
    for ext, spec in _BY_EXT.items():
        if lowered.endswith(ext):
            return spec
    return None


def strip_literals(line: str, spec: Optional[LanguageSpec] = None) -> str:
    """Blank out comments and string literals so a pattern sees only code.

    Without this a commented-out statement is reported as real code, and a
    pattern word quoted in a string is reported as a statement.
    """
    line_comments = spec.line_comments if spec else ("#",)
    strings = spec.strings if spec else ('"', "'")
    out = []
    i = 0
    quote = None
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in strings:
            quote = ch
            out.append(" ")
            i += 1
            continue
        if any(line.startswith(c, i) for c in line_comments):
            break
        out.append(ch)
        i += 1
    return "".join(out)