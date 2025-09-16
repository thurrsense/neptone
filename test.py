from django.template.loader import get_template
import django
from django.conf import settings
from pathlib import Path
python - <<'PY'
django.setup()

print("BASE_DIR:", settings.BASE_DIR)
print("TEMPLATE_DIRS:", settings.TEMPLATES[0]['DIRS'])

tpl = get_template('base.html')
print("FOUND:", tpl.origin)
PY
