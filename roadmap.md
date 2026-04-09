# Product Evolution Roadmap

This document illustrates the planned enhancements and progression paths for the TigerGate testing simulator.

## Phase 1: Foundation (Current)
- [x] Initial instantiation of generic Language frameworks (Python, Node, Ruby, Java, PHP).
- [x] Integration of native IaC vectors strictly mapping to CSPM, CIEM, KSPM definitions (Terraform).
- [x] Advanced modular extensions into Serverless, Supply Chain, and AI-SPM integrations.

## Phase 2: Orchestration (Near Future)
- [ ] Automate dynamic multi-cloud deployment scripts utilizing `Terraform Apply` bounded safely to a sandbox AWS/GCP account.
- [ ] Incorporate Helm charts for KSPM, natively deploying the vulnerable configurations directly to Minikube.
- [ ] Simulate active traffic generation pointing toward the GraphQL and OpenAPI environments.

## Phase 3: Reporting & Red Teaming (Long Term)
- [ ] Incorporate comprehensive GitOps mechanisms via ArgoCD templates for advanced pipeline evaluation.
- [ ] Write integration scripts to automatically pull exported TigerGate compliance checks to generate custom localized scoring metrics.
- [ ] Build interactive web-dashboard displaying "Expected vs Detected" security flaws natively.
