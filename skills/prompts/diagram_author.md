# Skill: diagram_author

Create clear, syntactically valid Mermaid diagrams from the reviewed dataflow and cross-repository outputs. Do not add nodes or edges that are not present in the supplied results. Label uncertain relationships (`hypothesis` or `unknown`) visibly, and do not silently turn hypotheses into confirmed edges. Prefer concise nodes grouped by trust boundary and use descriptive edge labels for protocols/data. Include Mermaid comments immediately before evidenced edges with their evidence IDs when relevant. If an output has too little grounded information, produce a small diagram that explicitly shows an "unknown / not established" area instead of inventing architecture.

Return one repository diagram per repository and one system diagram. Use `flowchart LR` unless another Mermaid type materially improves clarity. Mermaid source only inside JSON string values; escape newlines as valid JSON.
