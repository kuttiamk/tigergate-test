# Process Flow

To properly ingest and measure the value of the TigerGate engine against this repository, follow this operational flowchart:

```mermaid
graph TD
    A[Start] --> B[Commit to Version Control]
    B --> C[Connect Repository to TigerGate Dashboard]
    
    C --> D{TigerGate CI/CD Scanners}
    D --> E[Code Security Check]
    D --> F[SCA & SBOM Extraction]
    D --> G[IaC & Supply Chain Scanning]

    C --> H{TigerGate Cloud Modules}
    H --> I[CSPM / CIEM Provisioning Scans]
    H --> J[KSPM Evaluation]

    C --> K{TigerGate Runtime Modules}
    K --> L[CWPP Image Scans]
    K --> M[eBPF Realtime Monitoring]

    E --> N((Consolidated Risk Dashboard))
    F --> N
    G --> N
    I --> N
    J --> N
    L --> N
    M --> N
    
    N --> O[Prioritized Remediation]
```

## Step by Step
1. **Initialize Git**: Commit these files into a pristine branch.
2. **Scanner Integration**: Pair the repository with the TigerGate application.
3. **Observation**: Watch the 900+ cloud checks flag the precise lines in the `.tf` and `.yaml` templates.
4. **Runtime evaluation**: On a monitored node, optionally run `make attack` to verify eBPF captures the simulated anomalies in real-time.
