import json
import urllib.request

from classifier import classify
from rules_loader import load_rules


def fetch_split(split: str) -> list[dict]:
    rows: list[dict] = []
    page_size = 100
    offset = 0
    base_url = "https://datasets-server.huggingface.co/rows"

    while True:
        url = (
            f"{base_url}?dataset=deepset%2Fprompt-injections"
            f"&config=default&split={split}"
            f"&offset={offset}&length={page_size}"
        )
        with urllib.request.urlopen(url) as resp:
            body = json.loads(resp.read().decode("utf-8"))

        page = [r["row"] for r in body.get("rows", [])]
        rows.extend(page)

        if len(page) < page_size:
            break
        offset += page_size

    return rows


def main() -> None:
    ruleset = load_rules("heuristik.yaml")
    rows = fetch_split("train")

    attacks = [r for r in rows if r["label"] == 1]
    fns = [r["text"] for r in attacks if classify(r["text"], ruleset).score < 0.5]

    print(f"Total rows: {len(rows)}")
    print(f"Total attacks: {len(attacks)}")
    print(f"Total FN: {len(fns)}")
    for i, text in enumerate(fns[:30], 1):
        print(f"{i:3}. {text[:100]}")


if __name__ == "__main__":
    main()