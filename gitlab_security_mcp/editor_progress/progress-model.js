"use strict";

const activeStates = new Set(["RUNNING", "WAITING_FOR_HUMAN", "WAITING_FOR_AI"]);
const MAX_SNAPSHOT_BYTES = 256 * 1024;
const SNAPSHOT_TOO_LARGE = "Progress snapshot exceeds 256 KiB.";
const WORKFLOW_JOB_COUNT = 7;

function parseSnapshot(text) {
  if (text.length > MAX_SNAPSHOT_BYTES) throw new Error(SNAPSHOT_TOO_LARGE);
  const snapshot = JSON.parse(text);
  if (!snapshot || !Array.isArray(snapshot.tasks)) {
    throw new Error("Missing progress task array.");
  }
  if (!Number.isFinite(Date.parse(snapshot.updated_at))) {
    throw new Error("Invalid progress timestamp.");
  }
  for (const task of snapshot.tasks) {
    if (!task || !["id", "label", "status", "message", "updated_at"].every(
      key => typeof task[key] === "string"
    ) || !Number.isFinite(Date.parse(task.updated_at))) {
      throw new Error("Invalid progress task.");
    }
    if ((task.completed == null) !== (task.total == null) ||
        (task.total != null && (!Number.isInteger(task.total) ||
          !Number.isInteger(task.completed) || task.completed < 0 ||
          task.total < task.completed))) {
      throw new Error("Invalid progress counts.");
    }
    if (task.unit != null && typeof task.unit !== "string") throw new Error("Invalid progress unit.");
    if (task.jobs != null && (!Array.isArray(task.jobs) || task.jobs.length > WORKFLOW_JOB_COUNT ||
        task.jobs.some(job => !job || typeof job.label !== "string" ||
          typeof job.status !== "string" || !Number.isInteger(job.number)))) {
      throw new Error("Invalid workflow jobs.");
    }
  }
  return snapshot;
}

function taskText(task, now = Date.now()) {
  const age = Math.max(0, Math.floor((now - Date.parse(task.updated_at)) / 1000));
  const count = task.total == null ? "total unknown" : `${task.completed}/${task.total} ${task.unit || "files reviewed"}`;
  const stale = age > 30 ? `; awaiting update (${age}s)` : "";
  const jobs = (task.jobs || []).map(job => `\n${job.number}. ${job.label}: ${job.status}`).join("");
  return `${task.label}: ${task.status} | ${count} | ${task.message}${stale}${jobs}`;
}

module.exports = {
  activeStates,
  MAX_SNAPSHOT_BYTES,
  parseSnapshot,
  SNAPSHOT_TOO_LARGE,
  taskText,
  WORKFLOW_JOB_COUNT,
};
