from pathlib import Path

print(Path('message.txt').read_text(encoding='utf-8').strip())
