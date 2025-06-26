import os
import django
import io
from django.core.management import call_command

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')  # adjust if your settings path is different
django.setup()

with io.open('full_data.json', 'w', encoding='utf-8') as f:
    call_command('dumpdata',
                 exclude=['auth.permission', 'contenttypes', 'admin.logentry'],
                 indent=2,
                 stdout=f)
