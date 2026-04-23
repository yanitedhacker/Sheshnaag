import { useEffect, useState } from "react";
import { api } from "../api";
import type { V3SandboxProfileRecord } from "../types";

export function SandboxProfilesPage() {
  const [profiles, setProfiles] = useState<V3SandboxProfileRecord[]>([]);
  const [name, setName] = useState("URL sinkhole profile");
  const [profileType, setProfileType] = useState("url_analysis");
  const [providerHint, setProviderHint] = useState("lima");
  const [riskLevel, setRiskLevel] = useState("high");
  const [egressMode, setEgressMode] = useState("sinkhole");
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const data = await api.listSandboxProfiles();
    setProfiles(data.items);
  }

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load sandbox profiles."));
  }, []);

  async function createProfile() {
    try {
      await api.createSandboxProfile({
        name,
        profile_type: profileType,
        provider_hint: providerHint,
        risk_level: riskLevel,
        egress_mode: egressMode,
        config: {
          screenshot_capture: true,
          filesystem_rollback: true,
          fake_internet: egressMode === "fake_internet",
        },
      });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Sandbox profile creation failed.");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Sandbox Profiles</p>
          <h1>Hardened execution contracts for risky analysis</h1>
          <p className="page-copy">Capture provider preference, egress mode, and rollback controls for malware detonation, URL work, and mail analysis.</p>
        </div>
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}

      <section className="panel">
        <div className="form-grid">
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Profile name" />
          <select value={profileType} onChange={(event) => setProfileType(event.target.value)}>
            <option value="file_detonation">File detonation</option>
            <option value="url_analysis">URL analysis</option>
            <option value="email_analysis">Email analysis</option>
            <option value="static_only">Static only</option>
          </select>
          <select value={providerHint} onChange={(event) => setProviderHint(event.target.value)}>
            <option value="lima">Lima</option>
            <option value="docker_kali">Docker Kali</option>
          </select>
          <select value={riskLevel} onChange={(event) => setRiskLevel(event.target.value)}>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
          </select>
          <select value={egressMode} onChange={(event) => setEgressMode(event.target.value)}>
            <option value="default_deny">Default deny</option>
            <option value="sinkhole">Sinkhole</option>
            <option value="fake_internet">Fake internet</option>
            <option value="none">None</option>
          </select>
          <button className="primary-button" onClick={() => void createProfile()}>
            Add profile
          </button>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Profiles</h2>
          <span>{profiles.length}</span>
        </div>
        <div className="stack-list">
          {profiles.map((item) => (
            <article className="line-card" key={item.id}>
              <div>
                <strong>{item.name}</strong>
                <p>
                  {item.profile_type} · {item.provider_hint} · {item.egress_mode}
                </p>
                <p className="muted">Risk {item.risk_level}{item.is_default ? " · default" : ""}</p>
              </div>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}
