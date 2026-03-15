"""
HOLLOW_PURPLE — Policy Engine v2.0

Converts security policy definitions into runtime rules,
evaluates them against threat context, and produces
prioritized mitigation action plans.

Architecture:
    PolicyCompiler   → loads + compiles YAML/JSON policies into runtime Rule objects
    RuleEvaluator    → evaluates context against compiled rules, returns violations
    MitigationPlanner → maps violations to concrete action plans with priority + rollback

Usage:
    compiler = PolicyCompiler()
    compiler.load_directory("policies/")
    rules = compiler.get_rules()

    evaluator = RuleEvaluator(rules)
    violations = evaluator.evaluate(context)

    planner = MitigationPlanner()
    plan = planner.plan(violations, context)
    await planner.execute(plan)
"""

from policy_engine.policy_compiler import PolicyCompiler
from policy_engine.rule_evaluator import RuleEvaluator
from policy_engine.mitigation_planner import MitigationPlanner

__all__ = ["PolicyCompiler", "RuleEvaluator", "MitigationPlanner"]
__version__ = "2.0.0"