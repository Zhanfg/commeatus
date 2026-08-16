from pathlib import Path

path = Path("scripts/v05_release_prep.py")
text = path.read_text()
old = '''if OLD in readme.read_text():
    raise SystemExit("stale v0.4 release version remains in README")
'''
new = '''text = readme.read_text()
if OLD in text:
    readme.write_text(text.replace(OLD, NEW))
if OLD in readme.read_text():
    raise SystemExit("stale v0.4 release version remains in README")
'''
if text.count(old) != 1:
    raise SystemExit("release prep README-version assertion changed unexpectedly")
path.write_text(text.replace(old, new, 1))
