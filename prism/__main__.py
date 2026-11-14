"""Allow ``py -m prism`` and ``python -m prism`` to run the CLI.

The console script (``prism = prism.cli:main`` in pyproject) covers installs
made by pip; this module covers the case where a developer unzips the source
folder and runs the tool directly with the interpreter they already have, with
no install step of their own. Importing ``prism.cli`` runs the agent
registration decorators, same as the console entry point.
"""

from prism.cli import main

if __name__ == "__main__":
    main()