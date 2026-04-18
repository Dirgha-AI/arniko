import { pgTable, uuid, text, timestamp, jsonb, integer, varchar } from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";

export const scans = pgTable("arniko_scans", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  targetType: text("target_type").$type<"repository" | "container" | "llm" | "infrastructure">().notNull(),
  targetId: text("target_id").notNull(),
  tools: jsonb("tools").$type<string[]>().notNull().default([]),
  status: text("status").$type<"pending" | "running" | "completed" | "failed">().notNull().default("pending"),
  durationMs: integer("duration_ms"),
  error: text("error"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow(),
  completedAt: timestamp("completed_at", { withTimezone: true }),
});

export const findings = pgTable("arniko_findings", {
  id: uuid("id").primaryKey().defaultRandom(),
  scanId: uuid("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  tool: text("tool").notNull(),
  severity: text("severity").$type<"critical" | "high" | "medium" | "low" | "info">().notNull(),
  message: text("message").notNull(),
  file: text("file"),
  line: integer("line"),
  rule: text("rule"),
  metadata: jsonb("metadata"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow(),
});

export const scanRelations = relations(scans, ({ many }) => ({
  findings: many(findings),
}));

export const findingRelations = relations(findings, ({ one }) => ({
  scan: one(scans, {
    fields: [findings.scanId],
    references: [scans.id],
  }),
}));

export type Scan = typeof scans.$inferSelect;
export type NewScan = typeof scans.$inferInsert;
export type Finding = typeof findings.$inferSelect;
export type NewFinding = typeof findings.$inferInsert;
