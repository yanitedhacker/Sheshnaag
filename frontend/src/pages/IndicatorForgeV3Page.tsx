import { useEffect, useState } from "react";
import { api } from "../api";
import type { V3AnalysisCaseRecord, V3IndicatorRecord } from "../types";

export function IndicatorForgeV3Page() {
  const [cases, setCases] = useState<V3AnalysisCaseRecord[]>([]);
  const [items, setItems] = useState<V3IndicatorRecord[]>([]);
  const [analysisCaseId, setAnalysisCaseId] = useState<number>(0);
  const [indicatorKind, setIndicatorKind] = useState("domain");
  const [value, setValue] = useState("cdn-updates-example.invalid");
  const [source, setSource] = useState("browser_session");
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const [caseList, indicatorList] = await Promise.all([api.listAnalysisCases(), api.listIndicators()]);
    setCases(caseList.items);
    setItems(indicatorList.items);
    if (!analysisCaseId && caseList.items[0]) {
      setAnalysisCaseId(caseList.items[0].id);
    }
  }

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load indicators."));
  }, []);

  async function createIndicator() {
    if (!analysisCaseId) {
      return;
    }
    try {
      await api.createIndicator({
        analysis_case_id: analysisCaseId,
        indicator_kind: indicatorKind,
        value,
        source,
      });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Indicator creation failed.");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Indicator Forge</p>
          <h1>IOC extraction and clustering</h1>
          <p className="page-copy">Track domains, IPs, hashes, URLs, and other indicators under each analysis case for downstream prevention work.</p>
        </div>
      </div>
      {error ? <div className="panel error-panel">{error}</div> : null}
      <section className="panel">
        <div className="form-grid">
          <select value={analysisCaseId} onChange={(event) => setAnalysisCaseId(Number(event.target.value))}>
            {cases.map((item) => (
              <option key={item.id} value={item.id}>
                Case #{item.id} · {item.title}
              </option>
            ))}
          </select>
          <select value={indicatorKind} onChange={(event) => setIndicatorKind(event.target.value)}>
            <option value="domain">Domain</option>
            <option value="ip">IP</option>
            <option value="url">URL</option>
            <option value="hash">Hash</option>
            <option value="registry_key">Registry key</option>
          </select>
          <input value={value} onChange={(event) => setValue(event.target.value)} placeholder="Value" />
          <input value={source} onChange={(event) => setSource(event.target.value)} placeholder="Source" />
          <button className="primary-button" onClick={() => void createIndicator()}>
            Add indicator
          </button>
        </div>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Indicators</h2>
          <span>{items.length}</span>
        </div>
        <div className="stack-list">
          {items.map((item) => (
            <article className="line-card" key={item.id}>
              <div>
                <strong>{item.value}</strong>
                <p>
                  {item.indicator_kind} · {item.source ?? "unknown source"} · {Math.round(item.confidence * 100)}%
                </p>
              </div>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}
