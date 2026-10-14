from argparse import ArgumentParser
from pathlib import Path

from report import make_html


def main():
    parser = ArgumentParser()
    parser.add_argument('--input', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--template', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    page = make_html(Path(args.input), Path(args.config), Path(args.template))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(page.encode('utf-8'))
    print(f'Wrote {output.name}')


if __name__ == '__main__':
    main()
