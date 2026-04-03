import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

export function AssetExplorerPage() {
  const assets = useQuery({ queryKey: ["assets"], queryFn: api.getAssets });
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const selectedAssetId = selectedId ?? assets.data?.results[0]?.id ?? null;
  const assetDetail = useQuery({
    queryKey: ["asset", selectedAssetId],
    queryFn: () => api.getAsset(selectedAssetId!),
    enabled: selectedAssetId !== null,
  });
  const assetVulns = useQuery({
    queryKey: ["asset-vulns", selectedAssetId],
    queryFn: () => api.getAssetVulnerabilities(selectedAssetId!),
    enabled: selectedAssetId !== null,
  });
  const graph = useQuery({
    queryKey: ["graph-asset", selectedAssetId],
    queryFn: () => api.getGraph(selectedAssetId!),
    enabled: selectedAssetId !== null,
  });

  if (assets.isLoading) {
    return <section className="panel">Loading assets...</section>;
  }

  if (assets.error || !assets.data) {
    return <section className="panel">Unable to load assets.</section>;
  }

  return (
    <section className="asset-grid">
      <section className="list-card">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Asset Explorer</p>
            <h3>Infrastructure context</h3>
          </div>
        </div>

        <div className="action-list">
          {assets.data.results.map((asset) => (
            <article
              key={asset.id}
              className={`asset-card ${selectedAssetId === asset.id ? "active" : ""}`}
              onClick={() => setSelectedId(asset.id)}
            >
              <div className="list-row">
                <strong>{asset.name}</strong>
                {asset.is_crown_jewel && <span className="pill amber">crown jewel</span>}
              </div>
              <div className="inline-meta">
                <span>{asset.criticality}</span>
                <span>{asset.open_vulnerabilities} open vulns</span>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="detail-card">
        {assetDetail.data ? (
          <>
            <div className="panel-header">
              <div>
                <p className="eyebrow">Selected Asset</p>
                <h3>{assetDetail.data.name}</h3>
              </div>
              {assetDetail.data.is_crown_jewel && <span className="pill amber">Crown Jewel</span>}
            </div>

            <div className="inline-meta">
              <span>{assetDetail.data.environment}</span>
              <span>{assetDetail.data.criticality}</span>
              <span>{assetDetail.data.total_open_vulnerabilities} open vulnerabilities</span>
            </div>

            <div className="vuln-list">
              {(assetVulns.data ?? []).map((vuln) => (
                <article key={vuln.vulnerability_id} className="vuln-card">
                  <div className="list-row">
                    <Link to={`/cves/${vuln.cve_id}`}>{vuln.cve_id}</Link>
                    <span className="pill neutral">{vuln.risk_level ?? "UNSCORED"}</span>
                  </div>
                  <p className="muted">{vuln.description}</p>
                </article>
              ))}
            </div>

            <div className="panel">
              <p className="eyebrow">Attack Paths</p>
              <div className="path-list">
                {(graph.data?.paths ?? []).map((path) => (
                  <article key={path.summary} className="path-card">
                    {path.summary}
                  </article>
                ))}
              </div>
            </div>
          </>
        ) : (
          <p className="muted">Select an asset to inspect details.</p>
        )}
      </section>
    </section>
  );
}
