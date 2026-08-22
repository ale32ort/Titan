"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

type SecurityFinding = {
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
};

export default function SecurityFindingsPage() {
  const router = useRouter();

  const [findings, setFindings] =
    useState<SecurityFinding[]>([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);

  const [search, setSearch] =
    useState("");

  const [statusFilter, setStatusFilter] =
    useState("all");

  const [severityFilter, setSeverityFilter] =
    useState("all");

  const [ruleFilter, setRuleFilter] =
    useState("all");

  useEffect(() => {
    let cancelled = false;

    async function loadFindings() {
      try {
        const response = await fetch(
          "http://127.0.0.1:8001/api/v1/security/findings",
          {
            method: "GET",
            credentials: "include",
          }
        );

        if (!response.ok) {
          throw new Error(
            `Failed to load findings: ${response.status}`
          );
        }

        const data =
          await response.json();

        if (!cancelled) {
          setFindings(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to load security findings."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void loadFindings();

    return () => {
      cancelled = true;
    };
  }, []);

  const metrics = useMemo(() => {
    return {
      total: findings.length,

      open: findings.filter(
        (finding) =>
          finding.status === "open"
      ).length,

      investigating: findings.filter(
        (finding) =>
          finding.status === "investigating"
      ).length,

      resolved: findings.filter(
        (finding) =>
          finding.status === "resolved"
      ).length,

      highSeverity: findings.filter(
        (finding) =>
          finding.severity === "high"
      ).length,

      unassigned: findings.filter(
        (finding) =>
          !finding.assigned_to_user_id
      ).length,
    };
  }, [findings]);

  const availableRules = useMemo(() => {
    return Array.from(
      new Set(
        findings
          .map(
            (finding) =>
              finding.rule_id
          )
          .filter(
            (ruleId): ruleId is string =>
              ruleId !== null
          )
      )
    ).sort();
  }, [findings]);

  const filteredFindings = useMemo(() => {
    const normalizedSearch =
      search.trim().toLowerCase();

    return findings.filter(
      (finding) => {
        const matchesSearch =
          normalizedSearch === "" ||
          finding.subject
            .toLowerCase()
            .includes(
              normalizedSearch
            ) ||
          finding.finding_type
            .toLowerCase()
            .includes(
              normalizedSearch
            ) ||
          (
            finding.rule_id ?? ""
          )
            .toLowerCase()
            .includes(
              normalizedSearch
            );

        const matchesStatus =
          statusFilter === "all" ||
          finding.status ===
            statusFilter;

        const matchesSeverity =
          severityFilter === "all" ||
          finding.severity ===
            severityFilter;

        const matchesRule =
          ruleFilter === "all" ||
          finding.rule_id ===
            ruleFilter;

        return (
          matchesSearch &&
          matchesStatus &&
          matchesSeverity &&
          matchesRule
        );
      }
    );
  }, [
    findings,
    search,
    statusFilter,
    severityFilter,
    ruleFilter,
  ]);

  function clearFilters() {
    setSearch("");
    setStatusFilter("all");
    setSeverityFilter("all");
    setRuleFilter("all");
  }

  if (loading) {
    return (
      <main className="min-h-screen bg-slate-950 p-8 text-slate-100">
        Loading security findings...
      </main>
    );
  }

  if (error) {
    return (
      <main className="min-h-screen bg-slate-950 p-8 text-slate-100">
        <h1 className="text-3xl font-semibold">
          Titan Security Operations
        </h1>

        <p className="mt-4 text-red-400">
          {error}
        </p>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl p-8">
        <header className="mb-8">
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
            Security Operations Center
          </p>

          <h1 className="mt-2 text-3xl font-semibold tracking-tight">
            Titan Security Operations
          </h1>

          <p className="mt-2 text-slate-400">
            Security findings requiring analyst review.
          </p>
        </header>

        <section className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          <MetricCard
            label="Total"
            value={metrics.total}
          />

          <MetricCard
            label="Open"
            value={metrics.open}
          />

          <MetricCard
            label="Investigating"
            value={
              metrics.investigating
            }
          />

          <MetricCard
            label="Resolved"
            value={metrics.resolved}
          />

          <MetricCard
            label="High Severity"
            value={
              metrics.highSeverity
            }
          />

          <MetricCard
            label="Unassigned"
            value={metrics.unassigned}
          />
        </section>

        <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900/50 p-5">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
            <div className="xl:col-span-2">
              <label className="mb-2 block text-xs font-semibold uppercase tracking-[0.15em] text-slate-500">
                Search
              </label>

              <input
                value={search}
                onChange={(event) =>
                  setSearch(
                    event.target.value
                  )
                }
                placeholder="Search subject, finding, or rule..."
                className="w-full rounded-md border border-slate-700 bg-slate-950 px-4 py-2.5 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-slate-500"
              />
            </div>

            <FilterSelect
              label="Status"
              value={statusFilter}
              onChange={
                setStatusFilter
              }
              options={[
                {
                  value: "all",
                  label: "All statuses",
                },
                {
                  value: "open",
                  label: "Open",
                },
                {
                  value:
                    "investigating",
                  label:
                    "Investigating",
                },
                {
                  value: "resolved",
                  label: "Resolved",
                },
              ]}
            />

            <FilterSelect
              label="Severity"
              value={
                severityFilter
              }
              onChange={
                setSeverityFilter
              }
              options={[
                {
                  value: "all",
                  label:
                    "All severities",
                },
                {
                  value: "high",
                  label: "High",
                },
                {
                  value: "medium",
                  label: "Medium",
                },
                {
                  value: "low",
                  label: "Low",
                },
              ]}
            />

            <div>
              <label className="mb-2 block text-xs font-semibold uppercase tracking-[0.15em] text-slate-500">
                Rule
              </label>

              <select
                value={ruleFilter}
                onChange={(event) =>
                  setRuleFilter(
                    event.target.value
                  )
                }
                className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 outline-none focus:border-slate-500"
              >
                <option value="all">
                  All rules
                </option>

                {availableRules.map(
                  (ruleId) => (
                    <option
                      key={ruleId}
                      value={ruleId}
                    >
                      {ruleId}
                    </option>
                  )
                )}
              </select>
            </div>
          </div>

          <div className="mt-4 flex flex-col gap-3 border-t border-slate-800 pt-4 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-sm text-slate-500">
              Showing{" "}
              <span className="font-medium text-slate-300">
                {
                  filteredFindings.length
                }
              </span>{" "}
              of{" "}
              <span className="font-medium text-slate-300">
                {findings.length}
              </span>{" "}
              findings
            </p>

            <button
              onClick={clearFilters}
              className="text-left text-sm text-slate-400 hover:text-white"
            >
              Clear filters
            </button>
          </div>
        </section>

        {findings.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-700 p-8 text-center text-slate-500">
            No security findings found.
          </div>
        ) : filteredFindings.length ===
          0 ? (
          <div className="rounded-xl border border-dashed border-slate-700 p-8 text-center">
            <p className="text-slate-300">
              No findings match the
              current filters.
            </p>

            <button
              onClick={clearFilters}
              className="mt-3 text-sm text-slate-400 hover:text-white"
            >
              Clear filters
            </button>
          </div>
        ) : (
          <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1000px] text-left">
                <thead className="border-b border-slate-800 bg-slate-900">
                  <tr className="text-xs uppercase tracking-[0.12em] text-slate-500">
                    <th className="p-4">
                      Severity
                    </th>

                    <th className="p-4">
                      Finding
                    </th>

                    <th className="p-4">
                      Subject
                    </th>

                    <th className="p-4">
                      Status
                    </th>

                    <th className="p-4">
                      Owner
                    </th>

                    <th className="p-4">
                      Triggers
                    </th>

                    <th className="p-4">
                      Rule
                    </th>

                    <th className="p-4">
                      Last Seen
                    </th>
                  </tr>
                </thead>

                <tbody>
                  {filteredFindings.map(
                    (finding) => (
                      <tr
                        key={finding.id}
                        onClick={() =>
                          router.push(
                            `/security/findings/${finding.id}`
                          )
                        }
                        className="cursor-pointer border-b border-slate-800 transition last:border-b-0 hover:bg-slate-800/50"
                      >
                        <td className="p-4">
                          <SeverityBadge
                            severity={
                              finding.severity
                            }
                          />
                        </td>

                        <td className="p-4 font-medium text-slate-200">
                          {
                            finding.finding_type
                          }
                        </td>

                        <td className="p-4 text-slate-400">
                          {
                            finding.subject
                          }
                        </td>

                        <td className="p-4">
                          <StatusBadge
                            status={
                              finding.status
                            }
                          />
                        </td>

                        <td className="p-4 text-sm text-slate-400">
                          {finding.assigned_to_user_id
                            ? "Assigned"
                            : "Unassigned"}
                        </td>

                        <td className="p-4 text-slate-300">
                          {
                            finding.trigger_count
                          }
                        </td>

                        <td className="p-4 font-mono text-sm text-slate-400">
                          {finding.rule_id ??
                            "—"}
                        </td>

                        <td className="p-4 text-sm text-slate-500">
                          {new Date(
                            finding.last_seen
                          ).toLocaleString()}
                        </td>
                      </tr>
                    )
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}

function MetricCard({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
      <p className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-500">
        {label}
      </p>

      <p className="mt-2 text-2xl font-semibold text-slate-100">
        {value}
      </p>
    </div>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (
    value: string
  ) => void;
  options: {
    value: string;
    label: string;
  }[];
}) {
  return (
    <div>
      <label className="mb-2 block text-xs font-semibold uppercase tracking-[0.15em] text-slate-500">
        {label}
      </label>

      <select
        value={value}
        onChange={(event) =>
          onChange(
            event.target.value
          )
        }
        className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 outline-none focus:border-slate-500"
      >
        {options.map(
          (option) => (
            <option
              key={
                option.value
              }
              value={
                option.value
              }
            >
              {option.label}
            </option>
          )
        )}
      </select>
    </div>
  );
}

function SeverityBadge({
  severity,
}: {
  severity: string;
}) {
  return (
    <span className="inline-flex rounded-full border border-slate-700 px-2.5 py-1 text-xs font-semibold uppercase text-slate-300">
      {severity}
    </span>
  );
}

function StatusBadge({
  status,
}: {
  status: string;
}) {
  return (
    <span className="inline-flex rounded-full bg-slate-800 px-2.5 py-1 text-xs font-medium capitalize text-slate-300">
      {status}
    </span>
  );
}