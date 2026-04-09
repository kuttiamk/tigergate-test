# System Architecture

The simulated architecture encompasses a fictional hybrid-cloud deployment acting as the target environment for TigerGate. 

## Architectural Breakdown
- **Cloud Infrastructure Layer**: Multi-cloud simulation integrating simulated AWS S3, Oracle Block Storage, and Azure NSG components representing highly distributed data structures.
- **Microservices Layer**: API components functioning across monolithic `Java` endpoints, modern `Node.js` Express architectures, and serverless `AWS Lambda` functions.
- **Identity Layer**: An interconnected web of AWS IAM Roles and Azure RBAC assignments, intentionally demonstrating overly-broad cross-account trust vectors.
- **Data & Intelligence Layer**: Machine Learning SageMaker inferences (`ai_spm`) tightly coupled with Unencrypted `MySQL` databases configured to house PII schemas (`dspm`), illustrating high-value compromise targets.

When visualized by a CSPM or graph engine, this architecture will map multiple critically exposed ingress pathways natively connecting to sensitive internal resources.
