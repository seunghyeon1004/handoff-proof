import csv
import html
import json
from decimal import Decimal
from pathlib import Path


def make_html(data: Path, config_path: Path, template_path: Path) -> str:
    config = json.loads(config_path.read_text(encoding='utf-8'))
    if config['currency'] != 'KRW':
        raise ValueError('currency must be KRW')
    with data.open(newline='', encoding='utf-8') as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise ValueError('no spending rows')
    total = Decimal('0')
    items = []
    for row in rows:
        amount = Decimal(row['amount'])
        total += amount
        items.append(f"<li>{html.escape(row['item'])}: {amount} KRW</li>")
    template = template_path.read_text(encoding='utf-8')
    return (template.replace('{{TITLE}}', html.escape(config['title']))
            .replace('{{ROWS}}', ''.join(items))
            .replace('{{TOTAL}}', str(total)))
