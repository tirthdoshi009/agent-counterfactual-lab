import argparse
import asyncio
import json
from pathlib import Path

from lab.adapters.tool_calling import Budget
from lab.counterfactual import run_mechanics
from lab.simulation import simulate


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic Agent Boundary Lab local simulation")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser(
        "simulate", help="Loopback HTTP/MCP only; does not verify container or network isolation"
    )
    demo.add_argument("--output", type=Path, required=True)
    demo.add_argument("--repeat", type=int, choices=[1, 2, 3], default=2)
    counterfactual = commands.add_parser(
        "counterfactual", help="Manual four-condition mechanics; live inference remains disabled",
    )
    counterfactual.add_argument("--output", type=Path, required=True)
    counterfactual.add_argument(
        "--provider", choices=["deterministic-fake", "openai-compatible"], required=True,
    )
    counterfactual.add_argument("--trials", type=int, choices=range(1, 6), default=2)
    counterfactual.add_argument("--max-model-calls", type=int, choices=range(1, 9), default=4)
    counterfactual.add_argument("--max-tool-calls", type=int, choices=range(1, 13), default=6)
    counterfactual.add_argument("--max-output-tokens", type=int, default=384)
    counterfactual.add_argument("--max-reported-tokens", type=int, default=12000)
    args = parser.parse_args()
    if args.command == "counterfactual":
        if args.provider != "deterministic-fake":
            parser.error(
                "Live execution disabled: no provider/account/model is selected, no credential "
                "is authorized, and the changed broker isolation profile is not runtime verified. "
                "Use the separately approval-gated lab.broker_isolation entrypoint on an approved "
                "Linux host after selection. No request was sent; there is no scripted fallback."
            )
        budget = Budget(
            trials_per_condition=args.trials, max_model_calls=args.max_model_calls,
            max_tool_calls=args.max_tool_calls, max_output_tokens=args.max_output_tokens,
            max_reported_tokens=args.max_reported_tokens,
        )
        result = asyncio.run(run_mechanics(args.output, budget))
        print(json.dumps(result, indent=2))
        if result["inconclusive"]:
            raise SystemExit(1)
        return
    result = asyncio.run(simulate(args.output, args.repeat))
    print(json.dumps(result, indent=2))
    if result["unexpected_or_inconclusive"] or not result["repeatable"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
