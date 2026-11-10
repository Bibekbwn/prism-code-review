#!/bin/sh
# PRISM Pre-Commit Hook
# Runs PRISM review on staged files before allowing commit.
# Install: prism install-hook
# Or manually: copy this to .git/hooks/pre-commit and chmod +x

echo "PRISM: Running pre-commit review..."

# Run PRISM on staged changes with interactive prompts for medium/low findings
python -m prism.cli check-staged --prompt --json
EXIT_CODE=$?

# Show report interface after review completes
echo ""
echo "============================================"
echo "  PRISM Review Complete"
echo "============================================"
echo ""

if [ $EXIT_CODE -ne 0 ]; then
    echo "Commit blocked. Fix the issues above and try again."
    echo ""
    echo "View detailed report:"
    echo "  prism reports          # review history"
    echo "  prism dashboard        # visual timeline"
    echo "  prism feedback         # feedback loop stats"
    exit 1
else
    echo "All checks passed."
    echo ""
    echo "View report:"
    echo "  prism reports"
    exit 0
fi