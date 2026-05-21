#!/bin/sh
set -e
pip install --quiet build 2>&1 | tail -2
cd /repo/sdk
python -m build --wheel 2>&1 | tail -10
ls -la dist/
pip install --quiet --force-reinstall dist/*.whl 2>&1 | tail -2
python -c "from kya import score_agent; r = score_agent({'tools':['x']}); print('wheel install OK, score=', r.score)"
echo "── wheel contents (first 25 files) ──"
unzip -l dist/*.whl | head -28
