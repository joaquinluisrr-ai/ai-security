import yaml
with open("heuristik.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

for rule in config["rules"]:
    print(f"{rule['name']}: score={rule['score']}, cat={rule['category']}")
    from pydantic import BaseModel, Field

class Rule(BaseModel):
    name: str
    category: str
    score: float = Field(ge=0.0, le=1.0)
    pattern: str
    enabled: bool = True

class RuleSet(BaseModel):
    rules: list[Rule]

# Al cargar:
with open("heuristik.yaml", "r", encoding="utf-8") as f:
    raw = yaml.safe_load(f)

try:
    ruleset = RuleSet(**raw)
    for rule in ruleset.rules:
        print(rule.name, rule.score)
except Exception as e:
    print(f"Archivo de reglas inválido: {e}")