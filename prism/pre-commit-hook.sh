#!/bin/sh
# PRISM Pre-Commit Hook
# Runs PRISM review on staged files before allowing commit.
# Install: prism install-hook
# Or manually: copy this to .git/hooks/pre-commit and chmod +x

echo "PRISM: Running pre-commit review..."

# Run PRISM on staged changes with interactive prompts for medium/low findings
python -m prism.cli check-staged --prompt

# If PRISM exits with non-zero, block the commit
if [ $? -ne 0 ]; then
    echo ""
    echo "Commit blocked. Fix the issues above and try again."
    exit 1
fi

echo "PRISM: All checks passed."
exit 0