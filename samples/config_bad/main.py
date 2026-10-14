import json
from pathlib import Path

settings = json.loads(Path('config.json').read_text(encoding='utf-8'))
if settings['mode'] != 'ready':
    raise ValueError('mode must be ready')
print('CONFIG_OK')
