const capabilityCards = [
  {
    title: "Candidate Triage",
    body: "Score enterprise CVEs for research value using KEV, EPSS, environment fit, package matching, and lab observability.",
  },
  {
    title: "Constrained Kali Validation",
    body: "Launch local Kali-backed Docker validation plans with explicit network, mount, and capability boundaries.",
  },
  {
    title: "Evidence and Artifacts",
    body: "Turn each run into normalized evidence, defensive detections, mitigations, provenance records, and signed disclosure bundles.",
  },
];

const safetyItems = [
  "Defensive validation only. No target discovery, exploit brokerage, or public weaponized bundles.",
  "Local Linux-backed validation path with default-deny egress, ephemeral workspaces, and explicit analyst acknowledgement for sensitive runs.",
  "Evidence-first workflow with provenance, review history, and contribution ledger entries on meaningful outputs.",
];

const architectureCards = [
  {
    title: "Control Plane",
    body: "FastAPI backend for ingestion, scoring, recipes, runs, provenance, disclosures, and API docs.",
  },
  {
    title: "Validation Plane",
    body: "Provider abstraction with a first constrained Kali-on-Docker path and room for future Lima-backed secure mode.",
  },
  {
    title: "Knowledge Plane",
    body: "Raw-source preservation, LLM wiki patterns, and long-lived project memory for decisions, notes, and provenance context.",
  },
];

const roadmapSteps = [
  "Hard pivot from CVE Threat Radar to Sheshnaag product identity and safety posture.",
  "Candidate queue, recipe revisions, and simulated Kali validation runs.",
  "Evidence normalization, defensive artifact forge, provenance manifests, and disclosure exports.",
  "Future secure-mode expansion with VM-grade provider support and richer operator workflows.",
];

export function SupplyChainStoryPage() {
  return (
    <main id="top" className="marketing-page">
      <section className="hero-band">
        <div className="hero-copy">
          <p className="eyebrow">Local-First Defensive Research</p>
          <h1>Project Sheshnaag turns live CVE intelligence into constrained validation, defensive artifacts, and signed evidence.</h1>
          <p className="hero-lede">
            Built for enterprise software vulnerability research teams that need reproducible local workflows, safe Linux-backed
            validation, and disclosure-ready outputs without crossing into offensive operations.
          </p>
          <div className="button-row">
            <a className="primary-button" href="/docs" target="_blank" rel="noreferrer">
              Explore the API
            </a>
            <a className="ghost-button" href="/api/candidates?tenant_slug=demo-public" target="_blank" rel="noreferrer">
              View Demo Candidates
            </a>
          </div>
        </div>

        <aside className="hero-card">
          <p className="eyebrow">Current Focus</p>
          <strong>Real lab foundations first</strong>
          <ul className="simple-list">
            <li>Explainable candidate scoring</li>
            <li>Recipe revisioning and approval</li>
            <li>Constrained Kali validation plans</li>
            <li>Evidence, artifact, and provenance APIs</li>
          </ul>
        </aside>
      </section>

      <section id="platform" className="marketing-section">
        <div className="section-heading">
          <p className="eyebrow">Platform</p>
          <h2>What the first Sheshnaag release is built to do</h2>
        </div>
        <div className="marketing-grid marketing-grid-three">
          {capabilityCards.map((card) => (
            <article key={card.title} className="marketing-card">
              <h3>{card.title}</h3>
              <p>{card.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="safety" className="marketing-section section-accent">
        <div className="section-heading">
          <p className="eyebrow">Safety</p>
          <h2>Defensive boundaries are part of the product, not an afterthought.</h2>
        </div>
        <div className="marketing-grid marketing-grid-single">
          {safetyItems.map((item) => (
            <article key={item} className="marketing-card safety-card">
              <p>{item}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="architecture" className="marketing-section">
        <div className="section-heading">
          <p className="eyebrow">Architecture</p>
          <h2>Three planes working together</h2>
        </div>
        <div className="marketing-grid marketing-grid-three">
          {architectureCards.map((card) => (
            <article key={card.title} className="marketing-card architecture-card">
              <h3>{card.title}</h3>
              <p>{card.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="roadmap" className="marketing-section">
        <div className="section-heading">
          <p className="eyebrow">Roadmap</p>
          <h2>Shipping the pivot in clear steps</h2>
        </div>
        <div className="roadmap">
          {roadmapSteps.map((step, index) => (
            <article key={step} className="roadmap-step">
              <span>{`0${index + 1}`}</span>
              <p>{step}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="marketing-section cta-strip">
        <div>
          <p className="eyebrow">Backend First</p>
          <h2>The operator workflows now live behind the API while the full redesign comes later.</h2>
        </div>
        <div className="button-row">
          <a className="ghost-button" href="/health" target="_blank" rel="noreferrer">
            Health Check
          </a>
          <a className="primary-button" href="/api/intel/overview" target="_blank" rel="noreferrer">
            Sheshnaag Intel Overview
          </a>
        </div>
      </section>
    </main>
  );
}
