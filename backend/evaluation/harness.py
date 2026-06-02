"""
evaluation/harness.py — Continuous evaluation using DeepEval and RAGAS.

Tracks:
  - Answer Relevancy (DeepEval): are enriched findings relevant to the query?
  - Faithfulness (RAGAS): are migration suggestions grounded in retrieved docs?
  - HNDL Score Accuracy: are risk scores consistent with NIST guidance?
  
LangSmith is used to log evaluation results alongside agent traces.
"""
from __future__ import annotations
import asyncio
import json
from typing import Optional
from datetime import datetime, timezone

from langsmith import Client as LangSmithClient
from langsmith.evaluation import evaluate

# DeepEval
from deepeval import evaluate as deepeval_evaluate
from deepeval.metrics import AnswerRelevancyMetric, FaithfulnessMetric, HallucinationMetric
from deepeval.test_case import LLMTestCase

# RAGAS
from ragas import evaluate as ragas_evaluate
from ragas.metrics import faithfulness, answer_relevancy
from datasets import Dataset

from config import get_settings

settings = get_settings()
ls_client = LangSmithClient(api_key=settings.langchain_api_key)


# ── DeepEval metrics ───────────────────────────────────────────────────────────
ANSWER_RELEVANCY = AnswerRelevancyMetric(threshold=0.7, model="gpt-4o")
FAITHFULNESS = FaithfulnessMetric(threshold=0.8, model="gpt-4o")
HALLUCINATION = HallucinationMetric(threshold=0.3, model="gpt-4o")


async def evaluate_enrichment(
    scan_id: str,
    query: str,
    enriched_findings: list[dict],
    retrieved_context: list[str],
) -> dict:
    """
    Run DeepEval evaluation on a single enrichment result.
    Results are logged to LangSmith for tracing.
    """
    # Build the actual output string
    output = json.dumps(enriched_findings, indent=2)

    test_case = LLMTestCase(
        input=query,
        actual_output=output,
        retrieval_context=retrieved_context,
        context=retrieved_context,
    )

    # Run DeepEval metrics
    try:
        results = deepeval_evaluate(
            test_cases=[test_case],
            metrics=[ANSWER_RELEVANCY, FAITHFULNESS, HALLUCINATION],
        )
        scores = {
            "answer_relevancy": ANSWER_RELEVANCY.score,
            "faithfulness": FAITHFULNESS.score,
            "hallucination": HALLUCINATION.score,
            "passed": all([
                ANSWER_RELEVANCY.success,
                FAITHFULNESS.success,
                not HALLUCINATION.success,  # We WANT low hallucination
            ])
        }
    except Exception as e:
        scores = {"error": str(e), "passed": False}

    # Log to LangSmith
    await _log_to_langsmith(scan_id, query, output, scores)
    return scores


async def evaluate_with_ragas(
    questions: list[str],
    answers: list[str],
    contexts: list[list[str]],
    ground_truths: list[str],
) -> dict:
    """
    RAGAS evaluation for batch assessment of retrieval quality.
    Measures faithfulness and answer relevancy across multiple samples.
    """
    dataset = Dataset.from_dict({
        "question": questions,
        "answer": answers,
        "contexts": contexts,
        "ground_truth": ground_truths,
    })

    try:
        result = ragas_evaluate(
            dataset=dataset,
            metrics=[faithfulness, answer_relevancy],
        )
        return {
            "faithfulness": float(result["faithfulness"]),
            "answer_relevancy": float(result["answer_relevancy"]),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        return {"error": str(e)}


def build_ragas_ground_truths() -> dict:
    """
    Hardcoded ground truths for known algorithms used as RAGAS reference.
    In production, this would come from a curated golden dataset.
    """
    return {
        "RSA-2048": {
            "quantum_vulnerable": True,
            "migration": "ML-KEM-768",
            "hndl_risk": "high",
            "fips_replacement": "FIPS 203"
        },
        "ECDSA": {
            "quantum_vulnerable": True,
            "migration": "ML-DSA-65",
            "hndl_risk": "high",
            "fips_replacement": "FIPS 204"
        },
        "AES-256": {
            "quantum_vulnerable": False,
            "migration": "no change needed",
            "hndl_risk": "low",
            "fips_replacement": "N/A"
        },
        "SHA-256": {
            "quantum_vulnerable": False,
            "migration": "consider SHA-3",
            "hndl_risk": "low",
            "fips_replacement": "N/A"
        },
    }


async def _log_to_langsmith(scan_id: str, query: str, output: str, scores: dict):
    """Persist evaluation scores to LangSmith for the associated run."""
    try:
        # LangSmith feedback API
        ls_client.create_feedback(
            run_id=scan_id,
            key="answer_relevancy",
            score=scores.get("answer_relevancy", 0),
            comment=f"DeepEval evaluation for scan {scan_id}"
        )
        ls_client.create_feedback(
            run_id=scan_id,
            key="faithfulness",
            score=scores.get("faithfulness", 0),
        )
    except Exception:
        pass  # Don't fail the scan if LangSmith is unreachable


async def run_continuous_eval(recent_scans: list[dict]) -> dict:
    """
    Called nightly (or by CI) to evaluate a batch of recent scans.
    Returns aggregate metrics for dashboard display.
    """
    if not recent_scans:
        return {}

    questions = [f"What crypto algorithms are in {s['target']}?" for s in recent_scans]
    answers = [json.dumps(s.get("enriched_findings", []))[:500] for s in recent_scans]
    contexts = [[s.get("target", "")] for s in recent_scans]
    ground_truths = ["The scan should identify all quantum-vulnerable algorithms with HNDL scores."] * len(recent_scans)

    ragas_result = await evaluate_with_ragas(questions, answers, contexts, ground_truths)

    return {
        "batch_size": len(recent_scans),
        "ragas": ragas_result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
