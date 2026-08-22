"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";

type DetectionRule = {
  rule_id: string;
  name: string;
  description: string;
  severity: string;
  threshold: number | null;
  window_minutes: number | null;
  mitre_tactic: string | null;
  mitre_technique_id: string | null;
  mitre_technique_name: string | null;
};

type EvidenceEvent = {
  id: string;
  event_type: string;
  user_id: string | null;
  email: string | null;
  result: string;
  ip_address: string | null;
  user_agent: string | null;
  event_metadata: Record<string, unknown> | null;
  created_at: string;
};

type TriageRun = {
  id: string;
  finding_id: string;
  requested_by_user_id: string | null;
  provider: string;
  model: string;
  executive_summary: string;
  analyst_assessment: string;
  confirmed_facts: string[];
  hypotheses: string[];
  missing_context: string[];
  recommended_actions: string[];
  confidence: "low" | "medium" | "high";
  compromise_status:
    | "not_established"
    | "suspected"
    | "confirmed";
  grounding_corrections: string[];
  created_at: string;
};

type FindingDetail = {
  id: string;
  finding_type: string;
  subject: string;
  severity: string;
  status: string;
  assigned_to_user_id: string | null;
  trigger_count: number;
  rule_id: string | null;
  first_seen: string;
  last_seen: string;
  rule: DetectionRule | null;
  evidence_count: number;
  evidence: EvidenceEvent[];
};

type AnalystNote = {
  id: string;
  finding_id: string;
  author_user_id: string;
  content: string;
  created_at: string;
};

type CaseTimelineItem = {
  event_type: string;
  title: string;
  description: string;
  actor_user_id: string | null;
  created_at: string;
  metadata: Record<string, unknown>;
};

type FindingStatus =
  | "open"
  | "investigating"
  | "resolved";


export default function FindingDetailPage() {
  const params = useParams();
  const router = useRouter();

  const findingId = params.findingId as string;

  const [finding, setFinding] =
    useState<FindingDetail | null>(null);

  const [triageRuns, setTriageRuns] =
    useState<TriageRun[]>([]);

  const [notes, setNotes] =
    useState<AnalystNote[]>([]);

  const [timeline, setTimeline] =
    useState<CaseTimelineItem[]>([]);

  const [newNote, setNewNote] =
    useState("");

  const [savingNote, setSavingNote] =
    useState(false);

  const [loading, setLoading] =
    useState(true);

  const [triaging, setTriaging] =
    useState(false);

  const [updatingStatus, setUpdatingStatus] =
    useState(false);

  const [updatingAssignment, setUpdatingAssignment] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  async function loadCase() {
    try {
      const findingResponse = await fetch(
        `http://127.0.0.1:8001/api/v1/security/findings/${findingId}`,
        {
          credentials: "include",
        }
      );

      if (!findingResponse.ok) {
        throw new Error(
          `Failed to load finding: ${findingResponse.status}`
        );
      }

      const findingData =
        await findingResponse.json();

      const triageResponse = await fetch(
        `http://127.0.0.1:8001/api/v1/security/findings/${findingId}/triage-runs`,
        {
          credentials: "include",
        }
      );

      if (!triageResponse.ok) {
        throw new Error(
          `Failed to load triage history: ${triageResponse.status}`
        );
      }

      const triageData =
        await triageResponse.json();

      const notesResponse = await fetch(
        `http://127.0.0.1:8001/api/v1/security/findings/${findingId}/notes`,
        {
          credentials: "include",
        }
      );

      if (!notesResponse.ok) {
        throw new Error(
          `Failed to load analyst notes: ${notesResponse.status}`
        );
      }

      const timelineResponse = await fetch(
  `http://127.0.0.1:8001/api/v1/security/findings/${findingId}/timeline`,
  {
    credentials: "include",
  }
);

if (!timelineResponse.ok) {
  throw new Error(
    `Failed to load case timeline: ${timelineResponse.status}`
  );
}

const timelineData =
  await timelineResponse.json();

      const notesData =
        await notesResponse.json();

      setFinding(findingData);
      setTimeline(timelineData);
      setTriageRuns(triageData);
      setNotes(notesData);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load security case."
      );
    }
  }

  async function addAnalystNote() {
    const content = newNote.trim();

    if (!content) {
      return;
    }

    try {
      setSavingNote(true);
      setError(null);

      const response = await fetch(
        `http://127.0.0.1:8001/api/v1/security/findings/${findingId}/notes`,
        {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            content,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(
          `Failed to add analyst note: ${response.status}`
        );
      }

      const createdNote =
        await response.json();

      setNotes((current) => [
        createdNote,
        ...current,
      ]);

      setNewNote("");
      await loadCase();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to add analyst note."
      );
    } finally {
      setSavingNote(false);
    }
  }

  async function assignToMe() {
  try {
    setUpdatingAssignment(true);
    setError(null);

    const response = await fetch(
      `http://127.0.0.1:8001/api/v1/security/findings/${findingId}/assign-to-me`,
      {
        method: "POST",
        credentials: "include",
      }
    );

    if (!response.ok) {
      throw new Error(
        `Assignment failed: ${response.status}`
      );
    }

    await response.json();
    await loadCase();
  } catch (err) {
    setError(
      err instanceof Error
        ? err.message
        : "Unable to assign finding."
    );
  } finally {
    setUpdatingAssignment(false);
  }
}

async function unassignFinding() {
  try {
    setUpdatingAssignment(true);
    setError(null);

    const response = await fetch(
      `http://127.0.0.1:8001/api/v1/security/findings/${findingId}/unassign`,
      {
        method: "POST",
        credentials: "include",
      }
    );

    if (!response.ok) {
      throw new Error(
        `Unassign failed: ${response.status}`
      );
    }

    await response.json();
    await loadCase();
  } catch (err) {
    setError(
      err instanceof Error
        ? err.message
        : "Unable to unassign finding."
    );
  } finally {
    setUpdatingAssignment(false);
  }
}

  async function runAITriage() {
    try {
      setTriaging(true);
      setError(null);

      const response = await fetch(
        `http://127.0.0.1:8001/api/v1/security/findings/${findingId}/triage`,
        {
          method: "POST",
          credentials: "include",
        }
      );

      if (!response.ok) {
        throw new Error(
          `AI triage failed: ${response.status}`
        );
      }

      await response.json();
      await loadCase();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to run AI triage."
      );
    } finally {
      setTriaging(false);
    }
  }

  async function updateFindingStatus(
    newStatus: FindingStatus
  ) {
    try {
      setUpdatingStatus(true);
      setError(null);

      const response = await fetch(
        `http://127.0.0.1:8001/api/v1/security/findings/${findingId}/status`,
        {
          method: "PATCH",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            status: newStatus,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(
          `Status update failed: ${response.status}`
        );
      }
      await response.json();
      await loadCase();

      const updatedFinding =
        await response.json();

      setFinding((current) => {
        if (!current) {
          return current;
        }

        return {
          ...current,
          status: updatedFinding.status,
        };
      });
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to update finding status."
      );
    } finally {
      setUpdatingStatus(false);
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function loadInitialCase() {
      try {
        const findingResponse = await fetch(
          `http://127.0.0.1:8001/api/v1/security/findings/${findingId}`,
          {
            credentials: "include",
          }
        );

        if (!findingResponse.ok) {
          throw new Error(
            `Failed to load finding: ${findingResponse.status}`
          );
        }

        const findingData =
          await findingResponse.json();

        const triageResponse = await fetch(
          `http://127.0.0.1:8001/api/v1/security/findings/${findingId}/triage-runs`,
          {
            credentials: "include",
          }
        );

        if (!triageResponse.ok) {
          throw new Error(
            `Failed to load triage history: ${triageResponse.status}`
          );
        }

        const triageData =
          await triageResponse.json();

        const notesResponse = await fetch(
          `http://127.0.0.1:8001/api/v1/security/findings/${findingId}/notes`,
          {
            credentials: "include",
          }
        );

        if (!notesResponse.ok) {
          throw new Error(
            `Failed to load analyst notes: ${notesResponse.status}`
          );
        }

        const timelineResponse = await fetch(
  `http://127.0.0.1:8001/api/v1/security/findings/${findingId}/timeline`,
  {
    credentials: "include",
  }
);

if (!timelineResponse.ok) {
  throw new Error(
    `Failed to load case timeline: ${timelineResponse.status}`
  );
}

const timelineData =
  await timelineResponse.json();

        const notesData =
          await notesResponse.json();

        if (!cancelled) {
          setFinding(findingData);
          setTriageRuns(triageData);
          setNotes(notesData);
          setTimeline(timelineData);
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to load security case."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void loadInitialCase();

    return () => {
      cancelled = true;
    };
  }, [findingId]);

  if (loading) {
    return (
      <main className="min-h-screen bg-slate-950 p-8 text-slate-100">
        Loading security case...
      </main>
    );
  }

  if (error && !finding) {
    return (
      <main className="min-h-screen bg-slate-950 p-8 text-slate-100">
        <h1 className="text-2xl font-semibold">
          Titan Security Operations
        </h1>

        <p className="mt-4 text-red-400">
          {error}
        </p>
      </main>
    );
  }

  if (!finding) {
    return null;
  }

  const latestRun =
    triageRuns[0] ?? null;

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl p-8">
        <button
          onClick={() =>
            router.push("/security/findings")
          }
          className="mb-6 text-sm text-slate-400 hover:text-white"
        >
          ← Back to findings
        </button>

        <header className="mb-8 flex flex-col gap-4 border-b border-slate-800 pb-8 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
              Security Finding
            </p>

            <h1 className="text-3xl font-semibold tracking-tight">
              {finding.finding_type}
            </h1>

            <p className="mt-2 text-slate-400">
              {finding.subject}
            </p>
          </div>

          <button
            onClick={runAITriage}
            disabled={triaging}
            className="rounded-md bg-white px-5 py-3 font-medium text-slate-950 hover:bg-slate-200 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {triaging
              ? "Running AI Triage..."
              : "Run AI Triage"}
          </button>
        </header>

        {error && (
          <div className="mb-6 rounded-md border border-red-900 bg-red-950/40 p-4 text-red-300">
            {error}
          </div>
        )}

        <section className="mb-8 grid gap-4 md:grid-cols-2 lg:grid-cols-5">
          <MetricCard
            label="Severity"
            value={finding.severity.toUpperCase()}
          />

          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
            <p className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-500">
              Status
            </p>

            <select
              value={finding.status}
              disabled={updatingStatus}
              onChange={(event) =>
                void updateFindingStatus(
                  event.target.value as FindingStatus
                )
              }
              className="mt-2 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-semibold text-slate-100 disabled:opacity-50"
            >
              <option value="open">
                Open
              </option>

              <option value="investigating">
                Investigating
              </option>

              <option value="resolved">
                Resolved
              </option>
            </select>
          </div>

          <MetricCard
            label="Evidence"
            value={String(
              finding.evidence_count
            )}
          />

          <MetricCard
            label="Triggers"
            value={String(
              finding.trigger_count
            )}
          />

          <MetricCard
            label="Compromise"
            value={
              latestRun
                ? latestRun.compromise_status
                : "Not triaged"
            }
          />
        </section>

        <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900/50 p-6">
  <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
    <div>
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
        Case Ownership
      </p>

      <h2 className="mt-1 text-lg font-semibold">
        Assignment
      </h2>

      {finding.assigned_to_user_id ? (
        <p className="mt-2 text-sm text-slate-400">
          Assigned to analyst{" "}
          <span className="font-mono text-slate-200">
            {finding.assigned_to_user_id}
          </span>
        </p>
      ) : (
        <p className="mt-2 text-sm text-slate-400">
          This finding is currently unassigned.
        </p>
      )}
    </div>

    <div>
      {finding.assigned_to_user_id ? (
        <button
          onClick={unassignFinding}
          disabled={updatingAssignment}
          className="rounded-md border border-slate-700 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {updatingAssignment
            ? "Updating..."
            : "Unassign"}
        </button>
      ) : (
        <button
          onClick={assignToMe}
          disabled={updatingAssignment}
          className="rounded-md bg-white px-4 py-2 text-sm font-medium text-slate-950 hover:bg-slate-200 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {updatingAssignment
            ? "Assigning..."
            : "Assign to Me"}
        </button>
      )}
    </div>
  </div>
</section>

        <div className="grid gap-8 xl:grid-cols-[1fr_1.2fr]">
          <div className="space-y-8">
            <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
              <div className="mb-4">
                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
                  Detection
                </p>

                <h2 className="mt-1 text-xl font-semibold">
                  Rule Details
                </h2>
              </div>

              {finding.rule ? (
                <div className="space-y-4">
                  <div>
                    <p className="font-semibold">
                      {finding.rule.rule_id} —{" "}
                      {finding.rule.name}
                    </p>

                    <p className="mt-2 text-sm leading-6 text-slate-400">
                      {finding.rule.description}
                    </p>
                  </div>

                  <div className="grid gap-4 text-sm sm:grid-cols-2">
                    <InfoRow
                      label="Threshold"
                      value={
                        finding.rule.threshold !== null
                          ? String(
                              finding.rule.threshold
                            )
                          : "—"
                      }
                    />

                    <InfoRow
                      label="Window"
                      value={
                        finding.rule.window_minutes !== null
                          ? `${finding.rule.window_minutes} min`
                          : "—"
                      }
                    />

                    <InfoRow
                      label="MITRE Tactic"
                      value={
                        finding.rule.mitre_tactic ??
                        "—"
                      }
                    />

                    <InfoRow
                      label="MITRE Technique"
                      value={
                        finding.rule.mitre_technique_id
                          ? `${finding.rule.mitre_technique_id} ${finding.rule.mitre_technique_name ?? ""}`
                          : "—"
                      }
                    />
                  </div>
                </div>
              ) : (
                <p className="text-slate-400">
                  No rule metadata available.
                </p>
              )}
            </section>

            <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
              <div className="mb-5">
                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
                  Evidence
                </p>

                <h2 className="mt-1 text-xl font-semibold">
                  Event Timeline
                </h2>
              </div>

              <div className="space-y-3">
                {finding.evidence.map(
                  (event) => (
                    <div
                      key={event.id}
                      className="rounded-lg border border-slate-800 bg-slate-950/60 p-4"
                    >
                      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                        <span className="font-medium">
                          {event.event_type}
                        </span>

                        <span className="text-xs text-slate-500">
                          {new Date(
                            event.created_at
                          ).toLocaleString()}
                        </span>
                      </div>

                      <div className="mt-3 grid gap-2 text-sm text-slate-400 sm:grid-cols-3">
                        <span>
                          Result:{" "}
                          <strong className="text-slate-200">
                            {event.result}
                          </strong>
                        </span>

                        <span>
                          IP:{" "}
                          <strong className="text-slate-200">
                            {event.ip_address ??
                              "—"}
                          </strong>
                        </span>

                        <span>
                          Email:{" "}
                          <strong className="text-slate-200">
                            {event.email ??
                              "—"}
                          </strong>
                        </span>
                      </div>
                    </div>
                  )
                )}
              </div>
            </section>
          </div>

          <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
            <div className="mb-6 flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
                  AI Investigation
                </p>

                <h2 className="mt-1 text-xl font-semibold">
                  Grounded Triage History
                </h2>

                <p className="mt-2 text-sm text-slate-400">
                  Claude analysis validated by Titan policy.
                </p>
              </div>

              <span className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-400">
                {triageRuns.length} run
                {triageRuns.length === 1
                  ? ""
                  : "s"}
              </span>
            </div>

            {triageRuns.length === 0 ? (
              <div className="rounded-lg border border-dashed border-slate-700 p-8 text-center text-slate-500">
                No AI investigations yet.
              </div>
            ) : (
              <div className="space-y-6">
                {triageRuns.map(
                  (run, index) => (
                    <article
                      key={run.id}
                      className="rounded-xl border border-slate-800 bg-slate-950/60 p-5"
                    >
                      <div className="mb-5 flex flex-col gap-3 border-b border-slate-800 pb-4 sm:flex-row sm:items-center sm:justify-between">
                        <div>
                          <div className="flex items-center gap-2">
                            <h3 className="font-semibold">
                              {run.model}
                            </h3>

                            {index === 0 && (
                              <span className="rounded-full bg-slate-800 px-2 py-1 text-xs">
                                Latest
                              </span>
                            )}
                          </div>

                          <p className="mt-1 text-xs text-slate-500">
                            {new Date(
                              run.created_at
                            ).toLocaleString()}
                          </p>
                        </div>

                        <div className="flex gap-2 text-xs">
                          <Badge>
                            Confidence:{" "}
                            {run.confidence}
                          </Badge>

                          <Badge>
                            {run.compromise_status}
                          </Badge>
                        </div>
                      </div>

                      <div className="space-y-6">
                        <SectionBlock
                          title="Executive Summary"
                          text={
                            run.executive_summary
                          }
                        />

                        <SectionBlock
                          title="Analyst Assessment"
                          text={
                            run.analyst_assessment
                          }
                        />

                        <StringList
                          title="Confirmed Facts"
                          items={
                            run.confirmed_facts
                          }
                        />

                        <StringList
                          title="Hypotheses"
                          items={
                            run.hypotheses
                          }
                        />

                        <StringList
                          title="Missing Context"
                          items={
                            run.missing_context
                          }
                        />

                        <StringList
                          title="Recommended Actions"
                          items={
                            run.recommended_actions
                          }
                        />

                        {run
                          .grounding_corrections
                          .length > 0 && (
                          <div className="rounded-lg border border-amber-900/70 bg-amber-950/20 p-4">
                            <p className="font-medium text-amber-300">
                              Titan Grounding Corrections
                            </p>

                            <ul className="mt-3 space-y-2 text-sm text-amber-100/80">
                              {run.grounding_corrections.map(
                                (
                                  correction
                                ) => (
                                  <li
                                    key={
                                      correction
                                    }
                                  >
                                    •{" "}
                                    {correction}
                                  </li>
                                )
                              )}
                            </ul>
                          </div>
                        )}
                      </div>
                    </article>
                  )
                )}
              </div>
            )}
          </section>
        </div>

        <section className="mt-8 rounded-xl border border-slate-800 bg-slate-900/50 p-6">
          <div className="mb-6">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
              Human Investigation
            </p>

            <h2 className="mt-1 text-xl font-semibold">
              Analyst Notes
            </h2>

            <p className="mt-2 text-sm text-slate-400">
              Human-written investigation context preserved with this case.
            </p>
          </div>

          <div className="mb-6">
            <textarea
              value={newNote}
              onChange={(event) =>
                setNewNote(
                  event.target.value
                )
              }
              placeholder="Add investigation notes..."
              rows={4}
              className="w-full resize-none rounded-lg border border-slate-700 bg-slate-950 p-4 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-slate-500"
            />

            <div className="mt-3 flex justify-end">
              <button
                onClick={
                  addAnalystNote
                }
                disabled={
                  savingNote ||
                  !newNote.trim()
                }
                className="rounded-md bg-white px-4 py-2 text-sm font-medium text-slate-950 hover:bg-slate-200 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {savingNote
                  ? "Saving Note..."
                  : "Add Note"}
              </button>
            </div>
          </div>

          {notes.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-700 p-6 text-center text-slate-500">
              No analyst notes yet.
            </div>
          ) : (
            <div className="space-y-3">
              {notes.map(
                (note) => (
                  <article
                    key={note.id}
                    className="rounded-lg border border-slate-800 bg-slate-950/60 p-4"
                  >
                    <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                      <span className="text-xs text-slate-500">
                        Analyst{" "}
                        {
                          note.author_user_id
                        }
                      </span>

                      <span className="text-xs text-slate-500">
                        {new Date(
                          note.created_at
                        ).toLocaleString()}
                      </span>
                    </div>

                    <p className="mt-3 whitespace-pre-wrap text-sm leading-6 text-slate-300">
                      {note.content}
                    </p>
                  </article>
                )
              )}
            </div>
          )}
        </section> 
        <section className="mt-8 rounded-xl border border-slate-800 bg-slate-900/50 p-6">
  <div className="mb-6">
    <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
      Investigation History
    </p>

    <h2 className="mt-1 text-xl font-semibold">
      Case Activity
    </h2>

    <p className="mt-2 text-sm text-slate-400">
      Chronological record of activity associated with this security finding.
    </p>
  </div>

  {timeline.length === 0 ? (
    <div className="rounded-lg border border-dashed border-slate-700 p-6 text-center text-slate-500">
      No case activity available.
    </div>
  ) : (
    <div className="relative">
      <div className="absolute bottom-0 left-1.75 top-0 w-px bg-slate-800" />

      <div className="space-y-6">
        {[...timeline]
          .reverse()
          .map((item) => (
            <article
              key={`${item.event_type}-${item.created_at}`}
              className="relative pl-8"
            >
              <div className="absolute left-0 top-2 h-3.75 w-3.75 rounded-full border-2 border-slate-600 bg-slate-950" />

              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <p className="font-semibold text-slate-200">
                      {item.title}
                    </p>

                    <p className="mt-2 text-sm leading-6 text-slate-400">
                      {item.description}
                    </p>
                  </div>

                  <span className="shrink-0 text-xs text-slate-500">
                    {new Date(
                      item.created_at
                    ).toLocaleString()}
                  </span>
                </div>

                {item.actor_user_id && (
                  <p className="mt-3 text-xs text-slate-600">
                    Actor:{" "}
                    <span className="font-mono text-slate-500">
                      {item.actor_user_id}
                    </span>
                  </p>
                )}
              </div>
            </article>
          ))}
      </div>
    </div>
  )}
</section>
      </div>
    </main>
  );
}

function MetricCard({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
      <p className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-500">
        {label}
      </p>

      <p className="mt-2 font-semibold text-slate-100">
        {value}
      </p>
    </div>
  );
}

function InfoRow({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div>
      <p className="text-slate-500">
        {label}
      </p>

      <p className="mt-1 text-slate-200">
        {value}
      </p>
    </div>
  );
}

function Badge({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <span className="rounded-full border border-slate-700 px-3 py-1 text-slate-300">
      {children}
    </span>
  );
}

function SectionBlock({
  title,
  text,
}: {
  title: string;
  text: string;
}) {
  return (
    <div>
      <h4 className="mb-2 text-sm font-semibold text-slate-200">
        {title}
      </h4>

      <p className="text-sm leading-6 text-slate-400">
        {text}
      </p>
    </div>
  );
}

function StringList({
  title,
  items,
}: {
  title: string;
  items: string[];
}) {
  if (items.length === 0) {
    return null;
  }

  return (
    <div>
      <h4 className="mb-3 text-sm font-semibold text-slate-200">
        {title}
      </h4>

      <ul className="space-y-2">
        {items.map(
          (item) => (
            <li
              key={item}
              className="rounded-md bg-slate-900 p-3 text-sm leading-6 text-slate-400"
            >
              {item}
            </li>
          )
        )}
      </ul>
    </div>
  );
}