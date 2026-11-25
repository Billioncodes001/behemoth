import { formatDateTime, formatWhen } from "./time-format.ts";
import assert from "node:assert/strict";
import test from "node:test";

const sample = "2026-11-25 12:33:14.379269+00"; // Go RFC3339Nano, space separator (as stored)

test("formatDateTime renders locale-aware text without raw nanoseconds", () => {
  const en = formatDateTime(sample, "en-US");
  const expected = new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "short" }).format(
    new Date("2026-11-25T12:33:14.379269+00:00"),
  );
  assert.equal(en, expected);
  assert.ok(!en.includes("."), `nanoseconds leaked: ${en}`);

  const zh = formatDateTime(sample, "zh-CN");
  assert.notEqual(en, zh);
});

test("formatDateTime accepts RFC3339 with T separator", () => {
  assert.doesNotMatch(formatDateTime("2026-11-25T12:33:14Z", "en-US"), /^2026-11-25/);
});

test("formatDateTime passes through unparseable values and falls back for empties", () => {
  assert.equal(formatDateTime("not-a-date", "en-US"), "not-a-date");
  assert.equal(formatDateTime("", "en-US"), "—");
  assert.equal(formatDateTime(null, "en-US"), "—");
  assert.equal(formatDateTime(undefined, "en-US"), "—");
});

test("formatWhen uses relative labels within a week, absolute beyond", () => {
  const now = new Date("2026-11-25T13:00:00Z");
  assert.equal(formatWhen("2026-11-25 12:45:00+00", "en-US", now), "15m ago");
  assert.equal(formatWhen("2026-11-25 10:00:00+00", "en-US", now), "3h ago");
  assert.equal(formatWhen("2026-11-24 13:00:00+00", "en-US", now), "1d ago");
  assert.ok(!formatWhen("2026-11-01 00:00:00+00", "en-US", now).includes("ago"));
  assert.equal(formatWhen("2026-11-25 13:00:30+00", "en-US", now), "just now");
  assert.equal(formatWhen("", "en-US", now), "—");
});
