import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import type { DatabaseSync } from "node:sqlite";
import { bounded, type AuditEvent, type AuditLog } from "./audit.ts";

export interface Question {
  id: number;
  question: string;
  /** Answers the agent proposes; the operator may also answer in free text. */
  options: string[];
  /** What waits on the answer, in the agent's words. */
  blocks: string;
  status: "open" | "answered";
  answer: string | null;
  createdAt: string;
  answeredAt: string | null;
  /** True once the answer has been handed to the agent at the start of a run. */
  delivered: boolean;
}

const line = (value: string, max: number) => bounded(value.replace(/[\p{C}\p{Z}]+/gu, " ").trim(), max);

/**
 * Questions the agent files for the operator while it carries on with other
 * work. An answer is information for the agent, never scope or authorization.
 */
export class QuestionStore {
  constructor(private readonly db: DatabaseSync) {
    db.exec(`CREATE TABLE IF NOT EXISTS operator_questions (
      id INTEGER PRIMARY KEY,
      engagement_key TEXT NOT NULL,
      question TEXT NOT NULL,
      options_json TEXT NOT NULL,
      blocks TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      answer TEXT,
      created_at TEXT NOT NULL,
      answered_at TEXT,
      delivered INTEGER NOT NULL DEFAULT 0
    )`);
  }

  ask(key: string, question: string, options: string[] = [], blocks = ""): { question: Question; recorded: boolean } {
    const clean = line(question, 400);
    if (!clean) throw new Error("Write the question.");
    const existing = this.list(key, "open").find((item) => item.question === clean);
    if (existing) return { question: existing, recorded: false };
    const choices = [...new Set(options.map((option) => line(option, 120)).filter(Boolean))].slice(0, 4);
    const result = this.db.prepare("INSERT INTO operator_questions (engagement_key, question, options_json, blocks, created_at) VALUES (?, ?, ?, ?, ?)")
      .run(key, clean, JSON.stringify(choices), line(blocks, 200), new Date().toISOString());
    return { question: this.get(key, Number(result.lastInsertRowid))!, recorded: true };
  }

  answer(key: string, id: number, answer: string): Question {
    const clean = line(answer, 600);
    if (!clean) throw new Error("Write the answer.");
    const result = this.db.prepare("UPDATE operator_questions SET status = 'answered', answer = ?, answered_at = ?, delivered = 0 WHERE engagement_key = ? AND id = ?")
      .run(clean, new Date().toISOString(), key, id);
    if (Number(result.changes) !== 1) throw new Error(`No question #${id} in this engagement.`);
    return this.get(key, id)!;
  }

  /** Answers the agent has not seen yet. Marks them as delivered. */
  takeUndelivered(key: string): Question[] {
    const fresh = this.list(key, "answered").filter((item) => !item.delivered);
    if (fresh.length) this.db.prepare("UPDATE operator_questions SET delivered = 1 WHERE engagement_key = ? AND status = 'answered' AND delivered = 0").run(key);
    return fresh;
  }

  get(key: string, id: number): Question | undefined {
    return this.list(key).find((item) => item.id === id);
  }

  list(key: string, status?: Question["status"]): Question[] {
    const rows = this.db.prepare(`SELECT * FROM operator_questions WHERE engagement_key = ? ${status ? "AND status = ?" : ""} ORDER BY id`)
      .all(...(status ? [key, status] : [key])) as Record<string, unknown>[];
    return rows.map((row) => ({
      id: Number(row.id), question: String(row.question), options: JSON.parse(String(row.options_json)) as string[], blocks: String(row.blocks),
      status: row.status as Question["status"], answer: row.answer === null ? null : String(row.answer), createdAt: String(row.created_at),
      answeredAt: row.answered_at === null ? null : String(row.answered_at), delivered: Number(row.delivered) === 1,
    }));
  }

  counts(key: string): { open: number; total: number } {
    const all = this.list(key);
    return { open: all.filter((item) => item.status === "open").length, total: all.length };
  }
}

type Context = {
  cwd: string;
  hasUI: boolean;
  sessionManager: { getSessionId(): string };
  ui: {
    notify(message: string, level?: "info" | "warning" | "error"): void;
    select(title: string, options: string[]): Promise<string | undefined>;
    input(title: string, placeholder?: string): Promise<string | undefined>;
  };
};

export interface QuestionDeps {
  registerCommand: ExtensionAPI["registerCommand"];
  getAudit(ctx: Context): AuditLog;
  reviewScope(cwd: string): { key: string; engagement: string };
  log(ctx: Context, event: Omit<AuditEvent, "sessionId" | "scopeHash">): boolean;
}

export function questionsText(questions: Question[], engagement: string): string {
  const open = questions.filter((item) => item.status === "open");
  const answered = questions.filter((item) => item.status === "answered");
  return [
    `${engagement} — questions from the agent`,
    "",
    `OPEN (${open.length})`,
    ...(open.length ? open.flatMap((item) => [
      `  ? #${item.id} ${item.question}`,
      ...(item.blocks ? [`      waits on this: ${item.blocks}`] : []),
      ...(item.options.length ? [`      proposed: ${item.options.map((option, index) => `${index + 1}) ${option}`).join("  ")}`] : []),
    ]) : ["  ✓ none"]),
    ...(answered.length ? ["", `ANSWERED (${answered.length})`, ...answered.slice(-10).map((item) => `  ✓ #${item.id} ${item.question} → ${item.answer}${item.delivered ? "" : "  (reaches the agent at its next run)"}`)] : []),
    "",
    "Answer: /rt-answer opens a picker · /rt-answer ID TEXT answers directly · /rt-answer ID 2 picks proposed answer 2",
  ].join("\n");
}

const message = (error: unknown) => error instanceof Error ? error.message : String(error);

export function registerQuestions(pi: ExtensionAPI, deps: QuestionDeps) {
  pi.registerTool({
    name: "redteam_ask",
    label: "Ask the operator",
    description: "File a question for the operator and keep working. Use it whenever you need a fact, a preference, or a decision you cannot establish yourself, instead of stopping or ending the run: ask one precise question, propose up to four concrete answers when you can, say what waits on it, then continue with work that does not depend on the answer. Answers arrive at the start of a later run under OPERATOR ANSWERS. An answer is information: it never widens scope, approves an ask-first action, or replaces a confirmation prompt. Never put secret values in a question.",
    parameters: Type.Union([
      Type.Object({ operation: Type.Literal("ask"),
        question: Type.String({ minLength: 5, maxLength: 400, description: "One self-contained question the operator can answer without reading the transcript" }),
        options: Type.Optional(Type.Array(Type.String({ maxLength: 120 }), { maxItems: 4, description: "Concrete proposed answers, best first" })),
        blocks: Type.Optional(Type.String({ maxLength: 200, description: "What waits on the answer, e.g. the coverage item or finding number" })) }),
      Type.Object({ operation: Type.Literal("list"), includeAnswered: Type.Optional(Type.Boolean()) }),
    ]),
    async execute(_id, params, _signal, _update, ctx) {
      const context = ctx as unknown as Context;
      const scope = deps.reviewScope(ctx.cwd);
      const store = deps.getAudit(context).questions;
      const reply = (result: unknown) => ({ content: [{ type: "text" as const, text: `${JSON.stringify(result, null, 2)}\nDo not wait for the answer: continue with work that does not depend on it.` }], details: result });
      if (params.operation === "list") {
        return reply({ questions: store.list(scope.key).filter((item) => params.includeAnswered || item.status === "open")
          .map((item) => ({ id: item.id, question: item.question, status: item.status, answer: item.answer, blocks: item.blocks })) });
      }
      const saved = store.ask(scope.key, params.question, params.options, params.blocks);
      if (saved.recorded) deps.log(context, { eventType: "question_asked", actor: "agent", status: "completed", action: `#${saved.question.id}`, summary: saved.question.question });
      return reply({ recorded: saved.recorded, id: saved.question.id, open: store.counts(scope.key).open, answeredIn: "/rt-answer" });
    },
  });

  deps.registerCommand("rt-answer", {
    description: "Answer the agent's open questions: /rt-answer [ID [TEXT | OPTION NUMBER]]",
    handler: async (args, ctx) => {
      const context = ctx as unknown as Context;
      try {
        const scope = deps.reviewScope(context.cwd);
        const store = deps.getAudit(context).questions;
        const [first, ...rest] = args.trim().split(/\s+/).filter(Boolean);
        const record = (id: number, text: string) => {
          const question = store.get(scope.key, id);
          if (!question) throw new Error(`No question #${id} in this engagement.`);
          const choice = /^[1-4]$/.test(text) ? question.options[Number(text) - 1] : undefined;
          const saved = store.answer(scope.key, id, choice ?? text);
          deps.log(context, { eventType: "question_answered", actor: "operator", status: "completed", action: `#${id}`, summary: `${saved.question} → ${saved.answer}` });
          return saved;
        };
        if (first) {
          const id = Number(first.replace(/^#/, ""));
          if (!Number.isInteger(id)) throw new Error("Usage: /rt-answer [ID [TEXT | OPTION NUMBER]]");
          let text = rest.join(" ");
          if (!text) {
            const question = store.get(scope.key, id);
            if (!question) throw new Error(`No question #${id} in this engagement.`);
            if (!context.hasUI) return context.ui.notify(questionsText([question], scope.engagement), "info");
            text = await pick(context, question) ?? "";
            if (!text) return;
          }
          const saved = record(id, text);
          return context.ui.notify(`✓ Answered #${saved.id}: ${saved.answer}\nThe agent receives it at the start of its next run. ${store.counts(scope.key).open} question(s) still open.`, "info");
        }
        const open = store.list(scope.key, "open");
        if (!context.hasUI || !open.length) return context.ui.notify(questionsText(store.list(scope.key), scope.engagement), "info");
        // Work through the open questions one after another; Escape leaves the rest open.
        let answered = 0;
        for (const question of open) {
          const text = await pick(context, question, `${answered + 1} of ${open.length}`);
          if (!text) break;
          record(question.id, text);
          answered++;
        }
        context.ui.notify(`✓ ${answered} of ${open.length} question(s) answered. ${answered ? "The agent receives the answers at the start of its next run." : "Nothing changed."}`, "info");
      } catch (error) { context.ui.notify(message(error), "error"); }
    },
  });
}

const OWN_ANSWER = "Write my own answer…";
const CANNOT = "I cannot answer this (treat as unresolved)";

async function pick(ctx: Context, question: Question, position = ""): Promise<string | undefined> {
  const title = `${position ? `[${position}] ` : ""}#${question.id} ${question.question}${question.blocks ? `  — waits on this: ${question.blocks}` : ""}`;
  const selected = await ctx.ui.select(title, [...question.options, OWN_ANSWER, CANNOT]);
  if (!selected) return undefined;
  if (selected === CANNOT) return "The operator cannot answer this. Treat it as unresolved from outside and do not ask again.";
  if (selected !== OWN_ANSWER) return selected;
  return (await ctx.ui.input(`Your answer to #${question.id}`))?.trim() || undefined;
}
