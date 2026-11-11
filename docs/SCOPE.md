# Approval and spending boundary

Approved scope (2026-11-11): create a GitHub repository and implement the CPU-only simulator, data generator, baseline evaluator and tests.

This phase permits writing local source code, generating synthetic data, executing local Python unit tests, packaging the code and publishing the approved CPU-only scaffold to a new GitHub repository if repository creation is available.

This phase does **not** authorize: model download requiring license acceptance, model inference over paid APIs, fine-tuning, consuming substantial cloud credits, provisioning paid infrastructure, publishing a model or dataset to Hugging Face, opening external production integrations, registering a new paid service, or making a hackathon submission.

The current policies are **not** Cohere model baseline measurements. Do not interpret their scores as improved model safety. The simulator blocks all unauthorized actual executions by design. These are toy-world actions with no real-world effect.

The project intentionally has no dependencies for running and testing, no stored secrets, and no network calls. Its manual-only CI requires an explicit GitHub workflow trigger and has no automatic cloud job.

Future stages require separate approval with the exact action, resource usage, target repository and publication audience.
