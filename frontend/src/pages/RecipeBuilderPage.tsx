import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { Recipe, RecipeDiffResult, RecipeLintResult, TemplateItem } from "../types";

const DRAFT_KEY = "sheshnaag-recipe-builder-draft";

const COLLECTOR_IDS = [
  "process_tree",
  "package_inventory",
  "file_diff",
  "network_metadata",
  "service_logs",
  "tracee_events",
  "osquery_snapshot",
  "pcap",
  "falco_events",
  "tetragon_events",
] as const;

const DEFAULT_BASE_IMAGE = "kalilinux/kali-rolling:2026.1";

type TeardownMode = "destroy_immediately" | "retain_exports_only" | "retain_workspace_until_review";

type CandidateRow = {
  id: number;
  cve_id?: string | null;
  package_name?: string | null;
  title?: string | null;
};

function commandToText(cmd: unknown): string {
  if (Array.isArray(cmd)) {
    return cmd.map(String).join(" ");
  }
  if (typeof cmd === "string") {
    return cmd;
  }
  return "sleep 1";
}

function parseCommandText(text: string): string[] {
  const t = text.trim();
  if (!t) {
    return ["sleep", "1"];
  }
  return ["/bin/bash", "-lc", t];
}

function readNetworkPolicy(content: Record<string, unknown>): { mode: "none" | "bridge"; hosts: string } {
  const np = content.network_policy;
  if (np && typeof np === "object" && np !== null) {
    const o = np as Record<string, unknown>;
    const mode = o.mode === "bridge" ? "bridge" : "none";
    const hosts = o.allow_egress_hosts;
    const list = Array.isArray(hosts) ? hosts.map(String) : [];
    return { mode, hosts: list.join(", ") };
  }
  return { mode: "none", hosts: "" };
}

function readTeardownMode(content: Record<string, unknown>): TeardownMode {
  const tp = content.teardown_policy;
  if (tp && typeof tp === "object" && tp !== null) {
    const m = (tp as { mode?: string }).mode;
    if (m === "retain_exports_only" || m === "retain_workspace_until_review" || m === "destroy_immediately") {
      return m;
    }
  }
  const wr = content.workspace_retention;
  if (wr === "retain_workspace_until_review") {
    return "retain_workspace_until_review";
  }
  return "destroy_immediately";
}

function readCollectors(content: Record<string, unknown>): Set<string> {
  const c = content.collectors;
  if (!Array.isArray(c)) {
    return new Set(COLLECTOR_IDS);
  }
  return new Set(c.map(String));
}

function recipeSafetyHighlights(content: Record<string, unknown>): string[] {
  const warnings: string[] = [];
  const networkPolicy = (content.network_policy ?? {}) as Record<string, unknown>;
  const hosts = Array.isArray(networkPolicy.allow_egress_hosts) ? networkPolicy.allow_egress_hosts.map(String) : [];
  const selectedCollectors = Array.isArray(content.collectors) ? content.collectors.map(String) : [];
  const mounts = Array.isArray(content.mounts) ? content.mounts : [];
  const artifactInputs = Array.isArray(content.artifact_inputs) ? content.artifact_inputs : [];

  if (content.risk_level === "sensitive" || content.risk_level === "high") {
    warnings.push("This recipe will require an explicit analyst acknowledgement and an auditable provenance record before launch.");
  }
  if ((networkPolicy.mode === "bridge" || hosts.length > 0) && !selectedCollectors.includes("network_metadata")) {
    warnings.push("Bridge egress without the network metadata collector weakens outbound activity review.");
  }
  if (selectedCollectors.includes("tracee_events") && !selectedCollectors.includes("process_tree")) {
    warnings.push("Tracee without process_tree baseline can reduce runtime evidence explainability.");
  }
  if (mounts.some((mount) => typeof mount === "object" && mount !== null && (mount as Record<string, unknown>).read_only === false)) {
    warnings.push("Writable host mounts now require explicit approval metadata and will otherwise be rejected.");
  }
  if (artifactInputs.length > 0) {
    warnings.push("Artifact inputs are checksummed during transfer and must come from approved host roots.");
  }
  return warnings;
}

async function fetchCandidates(): Promise<CandidateRow[]> {
  const response = await fetch("/api/candidates?tenant_slug=demo-public&limit=50");
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Candidates request failed: ${response.status}`);
  }
  const data = (await response.json()) as { items?: CandidateRow[] };
  return data.items ?? [];
}

export function RecipeBuilderPage() {
  const [templates, setTemplates] = useState<TemplateItem[]>([]);
  const [recipes, setRecipes] = useState<Recipe[]>([]);
  const [candidates, setCandidates] = useState<CandidateRow[]>([]);
  const [recipeId, setRecipeId] = useState<number | null>(null);
  const [loadedRecipe, setLoadedRecipe] = useState<Recipe | null>(null);

  const [candidateId, setCandidateId] = useState<number | null>(null);
  const [templateId, setTemplateId] = useState<number | null>(null);
  const [distro, setDistro] = useState("kali");
  const [name, setName] = useState("");
  const [objective, setObjective] = useState("");
  const [createdBy, setCreatedBy] = useState("demo.analyst");
  const [updatedBy, setUpdatedBy] = useState("demo.analyst");
  const [commandText, setCommandText] = useState("sleep 1");
  const [collectors, setCollectors] = useState<Set<string>>(() => new Set(COLLECTOR_IDS));
  const [networkMode, setNetworkMode] = useState<"none" | "bridge">("none");
  const [egressHosts, setEgressHosts] = useState("");
  const [teardownMode, setTeardownMode] = useState<TeardownMode>("destroy_immediately");
  const [riskLevel, setRiskLevel] = useState<"standard" | "sensitive" | "high">("standard");

  const [lintResult, setLintResult] = useState<RecipeLintResult | null>(null);
  const [lintLoading, setLintLoading] = useState(false);
  const [diffOldRev, setDiffOldRev] = useState<number | null>(null);
  const [diffNewRev, setDiffNewRev] = useState<number | null>(null);
  const [diffResult, setDiffResult] = useState<RecipeDiffResult | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);

  const [approveOpen, setApproveOpen] = useState(false);
  const [reviewer, setReviewer] = useState("");
  const [analystName, setAnalystName] = useState("Demo Analyst");
  const [launchMode, setLaunchMode] = useState<"simulated" | "live">("simulated");

  const [busy, setBusy] = useState(false);
  const [banner, setBanner] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedTemplate = useMemo(
    () => templates.find((t) => t.id === templateId) ?? null,
    [templates, templateId],
  );

  const distros = useMemo(() => {
    const fromTemplates = [...new Set(templates.map((t) => t.distro).filter(Boolean))];
    const merged = new Set(["kali", "debian", "ubuntu", ...fromTemplates]);
    return [...merged];
  }, [templates]);

  const revisions = loadedRecipe?.revisions ?? [];
  const sortedRevisions = useMemo(
    () => [...revisions].sort((a, b) => b.revision_number - a.revision_number),
    [revisions],
  );

  const buildContent = useCallback((): Record<string, unknown> => {
    const baseImage = selectedTemplate?.base_image ?? DEFAULT_BASE_IMAGE;
    const hosts = egressHosts
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const requiresAck = riskLevel !== "standard";
    return {
      base_image: baseImage,
      distro,
      command: parseCommandText(commandText),
      collectors: COLLECTOR_IDS.filter((id) => collectors.has(id)),
      network_policy: {
        mode: networkMode,
        allow_egress_hosts: hosts,
      },
      teardown_policy: {
        mode: teardownMode,
        ephemeral_workspace: teardownMode !== "retain_workspace_until_review",
        retain_export_only: teardownMode === "retain_exports_only",
      },
      workspace_retention: teardownMode,
      risk_level: riskLevel,
      requires_acknowledgement: requiresAck,
    };
  }, [
    selectedTemplate,
    distro,
    commandText,
    collectors,
    networkMode,
    egressHosts,
    teardownMode,
    riskLevel,
  ]);

  const safetyHighlights = useMemo(() => recipeSafetyHighlights(buildContent()), [buildContent]);

  const hydrateFromContent = useCallback((content: Record<string, unknown>) => {
    setCommandText(commandToText(content.command));
    setCollectors(readCollectors(content));
    const nw = readNetworkPolicy(content);
    setNetworkMode(nw.mode);
    setEgressHosts(nw.hosts);
    setTeardownMode(readTeardownMode(content));
    const rl = content.risk_level;
    if (rl === "sensitive" || rl === "high") {
      setRiskLevel(rl);
    } else {
      setRiskLevel("standard");
    }
    const bi = content.base_image;
    if (typeof bi === "string" && bi) {
      const match = templates.find((t) => t.base_image === bi);
      if (match) {
        setTemplateId(match.id);
      }
    }
    const d = content.distro;
    if (typeof d === "string" && d) {
      setDistro(d);
    }
  }, [templates]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [rList, tList, cand] = await Promise.all([
          api.listRecipes().catch(() => ({ items: [], count: 0 })),
          api.listTemplates().catch(() => ({ items: [], count: 0 })),
          fetchCandidates().catch(() => []),
        ]);
        if (cancelled) {
          return;
        }
        setRecipes(rList.items);
        setTemplates(tList.items);
        setCandidates(cand);
        if (tList.items.length && templateId === null) {
          setTemplateId(tList.items[0].id);
        }
        if (cand.length && candidateId === null) {
          setCandidateId(cand[0].id);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to load initial data.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- initial load only
  }, []);

  useEffect(() => {
    if (!loadedRecipe?.revisions?.length) {
      return;
    }
    const current = loadedRecipe.revisions.reduce((best, r) =>
      r.revision_number > best.revision_number ? r : best,
    );
    hydrateFromContent(current.content as Record<string, unknown>);
  }, [loadedRecipe, hydrateFromContent]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const raw = localStorage.getItem(DRAFT_KEY);
        if (!raw) {
          return;
        }
        const d = JSON.parse(raw) as Record<string, unknown>;
        if (typeof d.name === "string") {
          setName(d.name);
        }
        if (typeof d.objective === "string") {
          setObjective(d.objective);
        }
        if (typeof d.commandText === "string") {
          setCommandText(d.commandText);
        }
        if (d.collectors && Array.isArray(d.collectors)) {
          setCollectors(new Set(d.collectors.map(String)));
        }
        if (d.networkMode === "bridge" || d.networkMode === "none") {
          setNetworkMode(d.networkMode);
        }
        if (typeof d.egressHosts === "string") {
          setEgressHosts(d.egressHosts);
        }
        if (
          d.teardownMode === "destroy_immediately" ||
          d.teardownMode === "retain_exports_only" ||
          d.teardownMode === "retain_workspace_until_review"
        ) {
          setTeardownMode(d.teardownMode);
        }
        if (d.riskLevel === "standard" || d.riskLevel === "sensitive" || d.riskLevel === "high") {
          setRiskLevel(d.riskLevel);
        }
        if (typeof d.distro === "string") {
          setDistro(d.distro);
        }
        if (typeof d.recipeId === "number") {
          setRecipeId(d.recipeId);
          try {
            const r = await api.getRecipe(d.recipeId);
            if (!cancelled) {
              setLoadedRecipe(r);
              setName(r.name);
              setObjective(r.objective);
              setCreatedBy(r.created_by);
              if (r.candidate_id != null) {
                setCandidateId(r.candidate_id);
              }
            }
          } catch {
            /* recipe may have been deleted */
          }
        }
      } catch {
        /* ignore */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleRecipeSelect = async (idStr: string) => {
    setError(null);
    setBanner(null);
    if (idStr === "" || idStr === "new") {
      setRecipeId(null);
      setLoadedRecipe(null);
      return;
    }
    const id = Number(idStr);
    setBusy(true);
    try {
      const r = await api.getRecipe(id);
      setRecipeId(r.id);
      setLoadedRecipe(r);
      setName(r.name);
      setObjective(r.objective);
      setCreatedBy(r.created_by);
      if (r.candidate_id != null) {
        setCandidateId(r.candidate_id);
      }
      const revs = r.revisions ?? [];
      if (revs.length) {
        const top = revs.reduce((a, b) => (a.revision_number > b.revision_number ? a : b));
        const bottom = revs.reduce((a, b) => (a.revision_number < b.revision_number ? a : b));
        setDiffOldRev(bottom.revision_number);
        setDiffNewRev(top.revision_number);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load recipe.");
    } finally {
      setBusy(false);
    }
  };

  const saveDraft = () => {
    const draft = {
      recipeId,
      name,
      objective,
      commandText,
      collectors: [...collectors],
      networkMode,
      egressHosts,
      teardownMode,
      riskLevel,
      distro,
    };
    localStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
    setBanner("Draft saved in this browser.");
  };

  const runLint = async () => {
    setLintLoading(true);
    setError(null);
    try {
      const result = await api.lintRecipe({
        tenant_slug: "demo-public",
        content: buildContent(),
      });
      setLintResult(result);
    } catch (e) {
      setLintResult({
        errors: [e instanceof Error ? e.message : "Lint request failed."],
        warnings: [],
        has_blocking_errors: true,
      });
    } finally {
      setLintLoading(false);
    }
  };

  const loadDiff = async () => {
    if (recipeId == null || diffOldRev == null || diffNewRev == null) {
      setError("Pick a recipe and two revision numbers for diff.");
      return;
    }
    setDiffLoading(true);
    setError(null);
    try {
      const d = await api.diffRecipeRevisions(recipeId, diffOldRev, diffNewRev);
      setDiffResult(d);
    } catch (e) {
      setDiffResult(null);
      setError(e instanceof Error ? e.message : "Diff request failed.");
    } finally {
      setDiffLoading(false);
    }
  };

  const createOrRevise = async () => {
    setBusy(true);
    setError(null);
    setBanner(null);
    const content = buildContent();
    const tenant_slug = "demo-public";
    try {
      if (recipeId == null) {
        if (candidateId == null) {
          throw new Error("Select a research candidate before creating a recipe.");
        }
        const created = await api.createRecipe({
          tenant_slug,
          candidate_id: candidateId,
          name: name.trim() || "Untitled recipe",
          objective: objective.trim() || "Validation objective",
          created_by: createdBy.trim() || "demo.analyst",
          content,
        });
        setRecipeId(created.id);
        setLoadedRecipe(created);
        setBanner(`Recipe created (revision ${created.current_revision_number}).`);
      } else {
        const updated = await api.addRecipeRevision(recipeId, {
          tenant_slug,
          updated_by: updatedBy.trim() || "demo.analyst",
          content,
        });
        setLoadedRecipe(updated);
        setBanner(`Revision ${updated.current_revision_number} created.`);
      }
      const list = await api.listRecipes();
      setRecipes(list.items);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed.");
    } finally {
      setBusy(false);
    }
  };

  const submitApprove = async () => {
    if (recipeId == null || !sortedRevisions.length) {
      setError("Load a recipe with at least one revision before approving.");
      return;
    }
    const revNum = sortedRevisions[0]?.revision_number;
    if (revNum == null) {
      return;
    }
    const r = reviewer.trim();
    if (!r) {
      setError("Enter reviewer name or email.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const updated = await api.approveRecipeRevision(recipeId, revNum, {
        tenant_slug: "demo-public",
        reviewer: r,
      });
      setLoadedRecipe(updated);
      setApproveOpen(false);
      setBanner(`Revision ${revNum} approved.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Approve failed.");
    } finally {
      setBusy(false);
    }
  };

  const launchBlocked = lintResult?.has_blocking_errors === true;

  const launchRun = async () => {
    if (recipeId == null || launchBlocked) {
      return;
    }
    const rev = sortedRevisions[0]?.revision_number ?? loadedRecipe?.current_revision_number;
    if (rev == null) {
      setError("No revision to launch.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.launchRun({
        tenant_slug: "demo-public",
        recipe_id: recipeId,
        revision_number: rev,
        analyst_name: analystName.trim() || "Demo Analyst",
        launch_mode: launchMode,
        acknowledge_sensitive: riskLevel !== "standard",
        workstation: { fingerprint: "recipe-builder-ui", hostname: "browser", os_family: "web" },
      });
      setBanner("Run launched. Check runs list in the API or ops tools.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Launch failed.");
    } finally {
      setBusy(false);
    }
  };

  const toggleCollector = (id: string) => {
    setCollectors((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  return (
    <div className="tw-min-h-screen tw-bg-gradient-to-br tw-from-[#0f0d0b] tw-via-[#1a1512] tw-to-[#12100e] tw-text-shesh-ink tw-pb-16">
      <div className="tw-max-w-6xl tw-mx-auto tw-px-4 tw-py-10">
        <header className="tw-mb-10">
          <p className="tw-text-xs tw-uppercase tw-tracking-[0.2em] tw-text-shesh-accent2/90 tw-mb-2">Lab</p>
          <h1 className="tw-text-3xl tw-font-semibold tw-tracking-tight tw-text-white">Recipe builder</h1>
          <p className="tw-mt-2 tw-text-shesh-muted tw-max-w-2xl tw-text-sm tw-leading-relaxed">
            Compose constrained validation recipes, lint policy, diff revisions, and launch approved runs against the demo
            tenant.
          </p>
        </header>

        {banner ? (
          <div className="tw-mb-6 tw-rounded-lg tw-border tw-border-shesh-accent2/35 tw-bg-shesh-accent2/10 tw-px-4 tw-py-3 tw-text-sm tw-text-shesh-accent2">
            {banner}
          </div>
        ) : null}
        {error ? (
          <div className="tw-mb-6 tw-rounded-lg tw-border tw-border-red-500/40 tw-bg-red-950/40 tw-px-4 tw-py-3 tw-text-sm tw-text-red-200">
            {error}
          </div>
        ) : null}
        {safetyHighlights.length ? (
          <section className="panel warning-panel tw-mb-6">
            <div className="panel-header">
              <h2>Safety warnings</h2>
              <span>{safetyHighlights.length} active</span>
            </div>
            <div className="stack-list">
              {safetyHighlights.map((warning) => (
                <article className="line-card" key={warning}>
                  <div>
                    <strong>Draft policy note</strong>
                    <p>{warning}</p>
                  </div>
                </article>
              ))}
            </div>
          </section>
        ) : null}

        <div className="tw-grid tw-gap-8 lg:tw-grid-cols-[1fr_380px]">
          <div className="tw-space-y-8">
            <section className="tw-rounded-2xl tw-border tw-border-shesh-line tw-bg-shesh-panel tw-p-6 tw-shadow-panel">
              <h2 className="tw-text-lg tw-font-medium tw-text-white tw-mb-4">Recipe</h2>
              <div className="tw-grid tw-gap-4 sm:tw-grid-cols-2">
                <label className="tw-block tw-space-y-1.5">
                  <span className="tw-text-xs tw-font-medium tw-text-shesh-muted">Existing recipe</span>
                  <select
                    className="tw-w-full tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-px-3 tw-py-2.5 tw-text-sm tw-text-shesh-ink focus:tw-outline-none focus:tw-ring-2 focus:tw-ring-shesh-accent/40"
                    value={recipeId != null ? String(recipeId) : "new"}
                    onChange={(e) => void handleRecipeSelect(e.target.value === "new" ? "new" : e.target.value)}
                    disabled={busy}
                  >
                    <option value="new">— New recipe —</option>
                    {recipes.map((r) => (
                      <option key={r.id} value={r.id}>
                        #{r.id} · {r.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="tw-block tw-space-y-1.5">
                  <span className="tw-text-xs tw-font-medium tw-text-shesh-muted">Candidate</span>
                  <select
                    className="tw-w-full tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-px-3 tw-py-2.5 tw-text-sm tw-text-shesh-ink focus:tw-outline-none focus:tw-ring-2 focus:tw-ring-shesh-accent/40"
                    value={candidateId ?? ""}
                    onChange={(e) => setCandidateId(e.target.value ? Number(e.target.value) : null)}
                    disabled={busy || recipeId != null}
                  >
                    <option value="">Select candidate…</option>
                    {candidates.map((c) => (
                      <option key={c.id} value={c.id}>
                        #{c.id} {c.cve_id ? `· ${c.cve_id}` : ""}{" "}
                        {c.package_name ? `· ${c.package_name}` : ""}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="tw-block tw-space-y-1.5 sm:tw-col-span-2">
                  <span className="tw-text-xs tw-font-medium tw-text-shesh-muted">Name</span>
                  <input
                    type="text"
                    className="tw-w-full tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-px-3 tw-py-2.5 tw-text-sm focus:tw-outline-none focus:tw-ring-2 focus:tw-ring-shesh-accent/40"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. CVE-2024-XXXX repro"
                  />
                </label>
                <label className="tw-block tw-space-y-1.5 sm:tw-col-span-2">
                  <span className="tw-text-xs tw-font-medium tw-text-shesh-muted">Objective</span>
                  <textarea
                    className="tw-w-full tw-min-h-[72px] tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-px-3 tw-py-2.5 tw-text-sm focus:tw-outline-none focus:tw-ring-2 focus:tw-ring-shesh-accent/40"
                    value={objective}
                    onChange={(e) => setObjective(e.target.value)}
                    placeholder="What this validation run should establish…"
                  />
                </label>
              </div>
            </section>

            <section className="tw-rounded-2xl tw-border tw-border-shesh-line tw-bg-shesh-panel tw-p-6 tw-shadow-panel">
              <h2 className="tw-text-lg tw-font-medium tw-text-white tw-mb-4">Environment</h2>
              <div className="tw-grid tw-gap-4 sm:tw-grid-cols-2">
                <label className="tw-block tw-space-y-1.5">
                  <span className="tw-text-xs tw-font-medium tw-text-shesh-muted">Template</span>
                  <select
                    className="tw-w-full tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-px-3 tw-py-2.5 tw-text-sm focus:tw-outline-none focus:tw-ring-2 focus:tw-ring-shesh-accent/40"
                    value={templateId ?? ""}
                    onChange={(e) => setTemplateId(e.target.value ? Number(e.target.value) : null)}
                  >
                    {templates.length === 0 ? (
                      <option value="">No templates (using default image)</option>
                    ) : null}
                    {templates.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.name} ({t.base_image})
                      </option>
                    ))}
                  </select>
                </label>
                <label className="tw-block tw-space-y-1.5">
                  <span className="tw-text-xs tw-font-medium tw-text-shesh-muted">Distro</span>
                  <select
                    className="tw-w-full tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-px-3 tw-py-2.5 tw-text-sm focus:tw-outline-none focus:tw-ring-2 focus:tw-ring-shesh-accent/40"
                    value={distro}
                    onChange={(e) => setDistro(e.target.value)}
                  >
                    {distros.map((d) => (
                      <option key={d} value={d}>
                        {d}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="tw-block tw-space-y-1.5 sm:tw-col-span-2">
                  <span className="tw-text-xs tw-font-medium tw-text-shesh-muted">Command (shell)</span>
                  <textarea
                    className="tw-w-full tw-min-h-[120px] tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-px-3 tw-py-2.5 tw-font-mono tw-text-xs tw-leading-relaxed focus:tw-outline-none focus:tw-ring-2 focus:tw-ring-shesh-accent/40"
                    value={commandText}
                    onChange={(e) => setCommandText(e.target.value)}
                    placeholder="sleep 1"
                  />
                  <span className="tw-text-[11px] tw-text-shesh-muted">
                    Executed as <code className="tw-text-shesh-accent2">/bin/bash -lc</code> with your script body.
                  </span>
                </label>
              </div>
            </section>

            <section className="tw-rounded-2xl tw-border tw-border-shesh-line tw-bg-shesh-panel tw-p-6 tw-shadow-panel">
              <h2 className="tw-text-lg tw-font-medium tw-text-white tw-mb-4">Collectors</h2>
              <div className="tw-grid tw-gap-3 sm:tw-grid-cols-2">
                {COLLECTOR_IDS.map((id) => (
                  <label
                    key={id}
                    className="tw-flex tw-cursor-pointer tw-items-center tw-gap-3 tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/20 tw-px-3 tw-py-2 tw-transition hover:tw-border-shesh-accent/30"
                  >
                    <input
                      type="checkbox"
                      className="tw-h-4 tw-w-4 tw-rounded tw-border-shesh-line tw-bg-black/40 tw-text-shesh-accent focus:tw-ring-shesh-accent/50"
                      checked={collectors.has(id)}
                      onChange={() => toggleCollector(id)}
                    />
                    <span className="tw-font-mono tw-text-xs tw-text-shesh-ink">{id}</span>
                  </label>
                ))}
              </div>
            </section>

            <section className="tw-rounded-2xl tw-border tw-border-shesh-line tw-bg-shesh-panel tw-p-6 tw-shadow-panel">
              <h2 className="tw-text-lg tw-font-medium tw-text-white tw-mb-4">Network & teardown</h2>
              <div className="tw-grid tw-gap-4 sm:tw-grid-cols-2">
                <label className="tw-block tw-space-y-1.5">
                  <span className="tw-text-xs tw-font-medium tw-text-shesh-muted">Network mode</span>
                  <select
                    className="tw-w-full tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-px-3 tw-py-2.5 tw-text-sm focus:tw-outline-none focus:tw-ring-2 focus:tw-ring-shesh-accent/40"
                    value={networkMode}
                    onChange={(e) => setNetworkMode(e.target.value as "none" | "bridge")}
                  >
                    <option value="none">none (isolated)</option>
                    <option value="bridge">bridge</option>
                  </select>
                </label>
                <label className="tw-block tw-space-y-1.5 sm:tw-col-span-2">
                  <span className="tw-text-xs tw-font-medium tw-text-shesh-muted">Egress hosts (comma-separated)</span>
                  <input
                    type="text"
                    className="tw-w-full tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-px-3 tw-py-2.5 tw-text-sm tw-font-mono focus:tw-outline-none focus:tw-ring-2 focus:tw-ring-shesh-accent/40"
                    value={egressHosts}
                    onChange={(e) => setEgressHosts(e.target.value)}
                    placeholder="e.g. deb.debian.org, security.ubuntu.com"
                    disabled={networkMode === "none"}
                  />
                </label>
                <label className="tw-block tw-space-y-1.5 sm:tw-col-span-2">
                  <span className="tw-text-xs tw-font-medium tw-text-shesh-muted">Teardown policy</span>
                  <select
                    className="tw-w-full tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-px-3 tw-py-2.5 tw-text-sm focus:tw-outline-none focus:tw-ring-2 focus:tw-ring-shesh-accent/40"
                    value={teardownMode}
                    onChange={(e) => setTeardownMode(e.target.value as TeardownMode)}
                  >
                    <option value="destroy_immediately">destroy_immediately</option>
                    <option value="retain_exports_only">retain_exports_only</option>
                    <option value="retain_workspace_until_review">retain_workspace_until_review</option>
                  </select>
                </label>
              </div>
            </section>

            <section className="tw-rounded-2xl tw-border tw-border-shesh-line tw-bg-shesh-panel tw-p-6 tw-shadow-panel">
              <h2 className="tw-text-lg tw-font-medium tw-text-white tw-mb-4">Risk</h2>
              <label className="tw-block tw-max-w-md tw-space-y-1.5">
                <span className="tw-text-xs tw-font-medium tw-text-shesh-muted">Risk level</span>
                <select
                  className="tw-w-full tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-px-3 tw-py-2.5 tw-text-sm focus:tw-outline-none focus:tw-ring-2 focus:tw-ring-shesh-accent/40"
                  value={riskLevel}
                  onChange={(e) => setRiskLevel(e.target.value as typeof riskLevel)}
                >
                  <option value="standard">standard</option>
                  <option value="sensitive">sensitive</option>
                  <option value="high">high</option>
                </select>
              </label>
            </section>
          </div>

          <aside className="tw-space-y-6">
            <section className="tw-rounded-2xl tw-border tw-border-shesh-line tw-bg-shesh-panel tw-p-6 tw-shadow-panel tw-sticky tw-top-6">
              <h2 className="tw-text-sm tw-font-semibold tw-uppercase tw-tracking-wider tw-text-shesh-muted tw-mb-4">
                Actions
              </h2>
              <div className="tw-flex tw-flex-col tw-gap-3">
                <button
                  type="button"
                  className="tw-w-full tw-rounded-lg tw-border tw-border-shesh-line tw-bg-white/5 tw-py-2.5 tw-text-sm tw-font-medium tw-text-shesh-ink tw-transition hover:tw-bg-white/10"
                  onClick={saveDraft}
                  disabled={busy}
                >
                  Save draft
                </button>
                <button
                  type="button"
                  className="tw-w-full tw-rounded-lg tw-bg-shesh-accent tw-py-2.5 tw-text-sm tw-font-semibold tw-text-black tw-shadow-lg tw-transition hover:tw-brightness-110 disabled:tw-opacity-50"
                  onClick={() => void createOrRevise()}
                  disabled={busy}
                >
                  {recipeId == null ? "Create recipe (rev 1)" : "Create revision"}
                </button>
                <button
                  type="button"
                  className="tw-w-full tw-rounded-lg tw-border tw-border-shesh-accent2/40 tw-bg-shesh-accent2/15 tw-py-2.5 tw-text-sm tw-font-medium tw-text-shesh-accent2 tw-transition hover:tw-bg-shesh-accent2/25"
                  onClick={() => void runLint()}
                  disabled={busy || lintLoading}
                >
                  {lintLoading ? "Linting…" : "Run lint"}
                </button>
                <button
                  type="button"
                  className="tw-w-full tw-rounded-lg tw-border tw-border-shesh-line tw-bg-white/5 tw-py-2.5 tw-text-sm tw-font-medium tw-text-shesh-ink tw-transition hover:tw-bg-white/10"
                  onClick={() => {
                    setApproveOpen((o) => !o);
                    setError(null);
                  }}
                  disabled={busy || recipeId == null}
                >
                  Approve latest revision…
                </button>
                {approveOpen ? (
                  <div className="tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/25 tw-p-3 tw-space-y-2">
                    <label className="tw-block tw-space-y-1">
                      <span className="tw-text-[11px] tw-text-shesh-muted">Reviewer</span>
                      <input
                        type="text"
                        className="tw-w-full tw-rounded-md tw-border tw-border-shesh-line tw-bg-black/40 tw-px-2 tw-py-2 tw-text-sm"
                        value={reviewer}
                        onChange={(e) => setReviewer(e.target.value)}
                        placeholder="Name or email"
                      />
                    </label>
                    <button
                      type="button"
                      className="tw-w-full tw-rounded-lg tw-bg-shesh-accent2/80 tw-py-2 tw-text-sm tw-font-semibold tw-text-black"
                      onClick={() => void submitApprove()}
                      disabled={busy}
                    >
                      Submit approval
                    </button>
                  </div>
                ) : null}

                <div className="tw-my-2 tw-h-px tw-bg-shesh-line" />

                <label className="tw-block tw-space-y-1">
                  <span className="tw-text-[11px] tw-text-shesh-muted">Analyst name</span>
                  <input
                    type="text"
                    className="tw-w-full tw-rounded-md tw-border tw-border-shesh-line tw-bg-black/40 tw-px-2 tw-py-2 tw-text-sm"
                    value={analystName}
                    onChange={(e) => setAnalystName(e.target.value)}
                  />
                </label>
                <label className="tw-block tw-space-y-1">
                  <span className="tw-text-[11px] tw-text-shesh-muted">Launch mode</span>
                  <select
                    className="tw-w-full tw-rounded-md tw-border tw-border-shesh-line tw-bg-black/40 tw-px-2 tw-py-2 tw-text-sm"
                    value={launchMode}
                    onChange={(e) => setLaunchMode(e.target.value as typeof launchMode)}
                  >
                    <option value="simulated">simulated</option>
                    <option value="live">live</option>
                  </select>
                </label>
                <button
                  type="button"
                  className="tw-w-full tw-rounded-lg tw-bg-gradient-to-r tw-from-shesh-accent tw-to-amber-500 tw-py-2.5 tw-text-sm tw-font-bold tw-text-black tw-shadow-lg tw-transition hover:tw-opacity-95 disabled:tw-cursor-not-allowed disabled:tw-opacity-40"
                  onClick={() => void launchRun()}
                  disabled={busy || recipeId == null || launchBlocked}
                  title={launchBlocked ? "Resolve lint errors before launch." : undefined}
                >
                  Launch run
                </button>
                {launchBlocked ? (
                  <p className="tw-text-center tw-text-[11px] tw-text-amber-200/90">Launch disabled while lint reports blocking errors.</p>
                ) : null}
              </div>

              <div className="tw-mt-6 tw-space-y-2 tw-text-[11px] tw-text-shesh-muted">
                <p>
                  <span className="tw-text-shesh-accent2">Created by</span> (new recipe)
                </p>
                <input
                  type="text"
                  className="tw-w-full tw-rounded-md tw-border tw-border-shesh-line tw-bg-black/40 tw-px-2 tw-py-1.5"
                  value={createdBy}
                  onChange={(e) => setCreatedBy(e.target.value)}
                  disabled={recipeId != null}
                />
                <p className="tw-pt-2">
                  <span className="tw-text-shesh-accent2">Updated by</span> (new revision)
                </p>
                <input
                  type="text"
                  className="tw-w-full tw-rounded-md tw-border tw-border-shesh-line tw-bg-black/40 tw-px-2 tw-py-1.5"
                  value={updatedBy}
                  onChange={(e) => setUpdatedBy(e.target.value)}
                />
              </div>
            </section>
          </aside>
        </div>

        <section className="tw-mt-10 tw-rounded-2xl tw-border tw-border-shesh-line tw-bg-shesh-panel tw-p-6 tw-shadow-panel">
          <div className="tw-flex tw-flex-wrap tw-items-end tw-justify-between tw-gap-4 tw-mb-4">
            <div>
              <h2 className="tw-text-lg tw-font-medium tw-text-white">Lint results</h2>
              <p className="tw-text-xs tw-text-shesh-muted">Errors block launch while this session shows blocking results.</p>
            </div>
          </div>
          {!lintResult ? (
            <p className="tw-text-sm tw-text-shesh-muted">Run lint to see results.</p>
          ) : (
            <div className="tw-grid tw-gap-4 md:tw-grid-cols-2">
              <div>
                <h3 className="tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-red-300 tw-mb-2">Errors</h3>
                <ul className="tw-space-y-1.5 tw-text-sm">
                  {lintResult.errors.length === 0 ? (
                    <li className="tw-text-shesh-muted">None</li>
                  ) : (
                    lintResult.errors.map((line, i) => (
                      <li key={i} className="tw-rounded-md tw-bg-red-950/50 tw-border tw-border-red-500/25 tw-px-3 tw-py-2 tw-text-red-100">
                        {line}
                      </li>
                    ))
                  )}
                </ul>
              </div>
              <div>
                <h3 className="tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-amber-200 tw-mb-2">Warnings</h3>
                <ul className="tw-space-y-1.5 tw-text-sm">
                  {lintResult.warnings.length === 0 ? (
                    <li className="tw-text-shesh-muted">None</li>
                  ) : (
                    lintResult.warnings.map((line, i) => (
                      <li
                        key={i}
                        className="tw-rounded-md tw-bg-amber-950/35 tw-border tw-border-amber-500/20 tw-px-3 tw-py-2 tw-text-amber-100"
                      >
                        {line}
                      </li>
                    ))
                  )}
                </ul>
              </div>
            </div>
          )}
        </section>

        <section className="tw-mt-8 tw-rounded-2xl tw-border tw-border-shesh-line tw-bg-shesh-panel tw-p-6 tw-shadow-panel">
          <h2 className="tw-text-lg tw-font-medium tw-text-white tw-mb-2">Revision diff</h2>
          <p className="tw-text-xs tw-text-shesh-muted tw-mb-4">
            Policy-relevant fields are highlighted. Requires a saved recipe with multiple revisions.
          </p>
          <div className="tw-flex tw-flex-wrap tw-items-end tw-gap-3 tw-mb-4">
            <label className="tw-space-y-1">
              <span className="tw-text-[11px] tw-text-shesh-muted">Old revision</span>
              <select
                className="tw-block tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-px-3 tw-py-2 tw-text-sm"
                value={diffOldRev ?? ""}
                onChange={(e) => setDiffOldRev(e.target.value ? Number(e.target.value) : null)}
              >
                <option value="">—</option>
                {sortedRevisions.map((r) => (
                  <option key={r.id} value={r.revision_number}>
                    r{r.revision_number} ({r.approval_state})
                  </option>
                ))}
              </select>
            </label>
            <label className="tw-space-y-1">
              <span className="tw-text-[11px] tw-text-shesh-muted">New revision</span>
              <select
                className="tw-block tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-px-3 tw-py-2 tw-text-sm"
                value={diffNewRev ?? ""}
                onChange={(e) => setDiffNewRev(e.target.value ? Number(e.target.value) : null)}
              >
                <option value="">—</option>
                {sortedRevisions.map((r) => (
                  <option key={`n-${r.id}`} value={r.revision_number}>
                    r{r.revision_number} ({r.approval_state})
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              className="tw-rounded-lg tw-bg-white/10 tw-px-4 tw-py-2 tw-text-sm tw-font-medium hover:tw-bg-white/15 disabled:tw-opacity-40"
              onClick={() => void loadDiff()}
              disabled={diffLoading || recipeId == null}
            >
              {diffLoading ? "Loading…" : "Load diff"}
            </button>
          </div>

          {diffResult ? (
            <div className="tw-space-y-4">
              {(diffResult.risk_level_changed || diffResult.collector_changes || diffResult.network_changes) && (
                <div className="tw-flex tw-flex-wrap tw-gap-2">
                  {diffResult.risk_level_changed ? (
                    <span className="tw-rounded-full tw-bg-amber-500/20 tw-px-3 tw-py-1 tw-text-[11px] tw-font-medium tw-text-amber-100">
                      Risk level changed
                    </span>
                  ) : null}
                  {diffResult.collector_changes ? (
                    <span className="tw-rounded-full tw-bg-violet-500/20 tw-px-3 tw-py-1 tw-text-[11px] tw-font-medium tw-text-violet-100">
                      Collector changes
                    </span>
                  ) : null}
                  {diffResult.network_changes ? (
                    <span className="tw-rounded-full tw-bg-sky-500/20 tw-px-3 tw-py-1 tw-text-[11px] tw-font-medium tw-text-sky-100">
                      Network changes
                    </span>
                  ) : null}
                </div>
              )}
              {diffResult.human_readable ? (
                <pre className="tw-whitespace-pre-wrap tw-rounded-lg tw-border tw-border-shesh-line tw-bg-black/30 tw-p-4 tw-font-mono tw-text-xs tw-text-shesh-muted">
                  {diffResult.human_readable}
                </pre>
              ) : null}
              <div className="tw-overflow-x-auto">
                <table className="tw-w-full tw-text-left tw-text-sm">
                  <thead>
                    <tr className="tw-border-b tw-border-shesh-line tw-text-xs tw-text-shesh-muted">
                      <th className="tw-py-2 tw-pr-4">Field</th>
                      <th className="tw-py-2 tw-pr-4">Old</th>
                      <th className="tw-py-2">New</th>
                    </tr>
                  </thead>
                  <tbody>
                    {diffResult.changes.map((ch, idx) => (
                      <tr
                        key={idx}
                        className={
                          ch.is_policy_relevant
                            ? "tw-border-b tw-border-amber-500/25 tw-bg-amber-500/10"
                            : "tw-border-b tw-border-shesh-line/60"
                        }
                      >
                        <td className="tw-py-2 tw-pr-4 tw-font-mono tw-text-xs">
                          {ch.field}
                          {ch.is_policy_relevant ? (
                            <span className="tw-ml-2 tw-rounded tw-bg-amber-500/25 tw-px-1.5 tw-py-0.5 tw-text-[10px] tw-text-amber-100">
                              policy
                            </span>
                          ) : null}
                        </td>
                        <td className="tw-py-2 tw-pr-4 tw-align-top tw-font-mono tw-text-xs tw-text-red-200/90">
                          {JSON.stringify(ch.old_value)}
                        </td>
                        <td className="tw-py-2 tw-align-top tw-font-mono tw-text-xs tw-text-emerald-200/90">
                          {JSON.stringify(ch.new_value)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <p className="tw-text-sm tw-text-shesh-muted">No diff loaded.</p>
          )}
        </section>
      </div>
    </div>
  );
}
