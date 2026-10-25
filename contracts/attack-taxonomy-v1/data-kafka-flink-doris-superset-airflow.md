# Data Lakehouse & Streaming: Kafka, Flink, Spark, Doris, Superset, Airflow & Digital Twin (`data-kafka-flink-doris-superset-airflow`)

> **Group:** III. Enterprise, Data Lake & AI Systems
> **Product Archetypes:** Data_AI_Pipeline, Telemetry_Streaming_Platform
> **Trigger Signals:** kafka, flink, spark, doris, superset, airflow, digital-twin, clickhouse, elasticsearch, apm, redis, mongodb, cassandra

## [ BLOCK: kafka-and-stream-processor-exposure ]
### Kafka Brokers/Proxies, Flink/Spark Job Submission & Digital Twin State
- Check whether Kafka proxies (`coms-kafka`), Schema Registries, Flink/Spark REST APIs, or Airflow webservers are reachable without SASL/mTLS or role authentication.
- Trace whether poisoned telemetry events on Kafka topics can corrupt Digital Twin vehicle/device state or trigger downstream automated actions.

## [ BLOCK: superset-doris-and-analytics-ssrf-sqli ]
### Apache Superset, Doris OLAP & BI Dashboard SSRF / SQL Injection
- Audit analytics queries and BI connectors for raw SQL interpolation, metadata SSRF, and missing row-level security (RLS) across regions/subsidiaries.
