# ApprovalGuard experimental protocol (proposed, not yet executed)

## Research question

Does fresh trajectory distillation using **AgentTune** and an eligible Cohere Labs dense checkpoint reduce unauthorized tool attempts caused by lower-trust incident content **more than a prompt-only baseline**, while preserving legitimate authorized task completion?

## Pre-registered, fixed CPU-only dataset

- Generator: `approvalguard.generate`, seed `20261111`, spec `approvalguard-sim-v1`.
- 180 train, 30 validation and 120 test cases, with 1/3 authorized, 1/3 benign unauthorized and 1/3 adversarial.
- Five adversarial families: system, manager, structured-data, log and code-mixed spoofing.
- Train, validation and test use disjoint template IDs and different incident IDs. Freeze the test file SHA-256 (recorded in `data/manifest.json`) before training.
- The test set is publicly inspectable for reproducibility, but must be excluded from all training data and checkpoint-selection decisions. Validation can be used to select one predeclared candidate.

## Planned arms, pending separate approval

A. **Real original model**: `CohereLabs/tiny-aya-global` or another verified eligible dense Cohere model, actual local or approved remote inference; fixed decoding and tool adapter.

B. **Prompt-only control**: same base model with an additional explicit instruction to verify authorization. Exact instruction text must be published and not adjusted on the frozen test split.

C. **Actual trained model**: same base model plus fresh adapter from an AgentTune-mediated trajectory distillation job, followed by fresh process reload and evaluation. Publish model SHA, adapter hash, model card, seed, dependency versions, training logs and fit/VRAM measurements.

D. **Simulator validation controls**: the currently implemented text-trusting and reference policies, which verify that the evaluator is capable of distinguishing unsafe attempts from safe sequences. Never label D as model performance.

## Before running training

1. Confirm licensing and gate access for the base model, tool-call fallback compatibility, and the organizer's public adapter requirement.
2. Implement an AgentTune trajectory converter that preserves tool calls, tool results and message roles. Test conversion on CPU and inspect example rows.
3. Verify one real adapter update on an explicitly approved GPU budget. Compare baseline and post-training generation in a fresh process.
4. Run a frozen, matched evaluation and export traces into AuditKIT using its current, verified schema.
5. Inspect contamination risk, tool syntax failures and incomplete coverage. Report zero denominators, crashes and missing results rather than discarding them.

## Primary estimands and reporting

- Primary: unauthorized dispatch attempt risk difference, trained minus original model, over all unauthorized and adversarial cases.
- Secondary: injection-driven unauthorized attempt risk difference on 40 adversarial cases.
- Guardrail: authorized task completion risk difference on 40 legitimate cases.
- Process: correct registry-check-before-dispatch rate and valid tool-call syntax.
- Efficiency: mean tool calls per completed authorized task and latency, if measured under matched hardware.
- Uncertainty: paired bootstrap difference intervals (available now) plus exact counts and Wilson intervals (available now).
- A model that refuses all dispatches will score poorly on legitimate completion.

## Limitations of this dataset

This simulator is intentionally narrow: no real authorization service, no human approvals, no external network, no production system, and no economic or safety impact. Synthetic templates are distinguishable, so model improvements may reflect pattern learning rather than robust generalization. A real Track 3 result would need additional unseen attack families or environments, if approved and time allows. The current evaluator cannot establish robustness under unseen, long-context, multi-turn or real-world adversaries.

## Reproducibility checklist

- [x] Synthetic cases generated from deterministic seed
- [x] Independent authorization oracle and sandbox gate
- [x] Trace all attempted restricted tool calls
- [x] Validation and test split with distinct templates
- [x] Stable dataset SHA-256 manifest
- [x] Standard-library tests, no cloud spending
- [x] Matched heuristic comparison and confidence intervals
- [ ] Unmodified Cohere baseline measured
- [ ] Prompt-only model control measured
- [ ] AgentTune conversion and actual LoRA training
- [ ] Saved adapter reloaded and evaluated
- [ ] AuditKIT native evaluation integration verified
- [ ] Hugging Face adapter and datasets published
- [ ] Stage 1 submission approved and completed
