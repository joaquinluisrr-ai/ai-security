# evaluate.py
import json
import urllib.request

from classifier import classify
from rules_loader import load_rules


THRESHOLD = 0.5


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

    tp = fp = tn = fn = 0
    false_positives: list[str] = []
    false_negatives: list[str] = []

    for row in rows:
        text = row["text"]
        label = row["label"]

        result = classify(text, ruleset)
        predicted_attack = result.score >= THRESHOLD

        if label == 1 and predicted_attack:
            tp += 1
        elif label == 1 and not predicted_attack:
            fn += 1
            false_negatives.append(text)
        elif label == 0 and predicted_attack:
            fp += 1
            false_positives.append(text)
        else:
            tn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    print(f"Threshold: {THRESHOLD}")
    print(f"Total examples: {total}")
    print()
    print(f"TP: {tp}  FP: {fp}  TN: {tn}  FN: {fn}")
    print()
    print(f"Precision: {precision:.2%}")
    print(f"Recall:    {recall:.2%}")
    print(f"Accuracy:  {accuracy:.2%}")

    print("\n--- First 5 false positives ---")
    for text in false_positives[:5]:
        print(f"  - {text[:100]!r}")

    print("\n--- First 5 false negatives ---")
    for text in false_negatives[:5]:
        print(f"  - {text[:100]!r}")


if __name__ == "__main__":
    main()