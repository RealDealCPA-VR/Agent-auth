import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { db } from '../db/index.js';

/**
 * One error envelope for the entire API:
 *   { "error": { "code": "...", "message": "...", "requestId": "..." } }
 */
export interface ErrorEnvelope {
  error: { code: string; message: string; requestId: string; details?: unknown };
}

export function errorBody(
  req: FastifyRequest,
  code: string,
  message: string,
  details?: unknown,
): ErrorEnvelope {
  return {
    error: { code, message, requestId: req.id, ...(details === undefined ? {} : { details }) },
  };
}

/** Send a standardized error response. */
export function fail(
  req: FastifyRequest,
  reply: FastifyReply,
  status: number,
  code: string,
  message: string,
  details?: unknown,
): FastifyReply {
  return reply.code(status).send(errorBody(req, code, message, details));
}

// --- Pagination -------------------------------------------------------------

export const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).max(1_000_000).default(0),
});

export type Pagination = z.infer<typeof paginationSchema>;

export interface Page<T> {
  items: T[];
  // `total` is the full count of rows matching the query (not just this page),
  // so clients know how many pages exist. `returned` is this page's size.
  pagination: { limit: number; offset: number; total: number; returned: number };
}

export function page<T>(items: T[], p: Pagination, total: number): Page<T> {
  return {
    items,
    pagination: { limit: p.limit, offset: p.offset, total, returned: items.length },
  };
}

/** The transaction handle drizzle passes to a `db.transaction` callback. */
type Tx = Parameters<Parameters<typeof db.transaction>[0]>[0];

/**
 * Run a list query and its matching COUNT inside one read-only, repeatable-read
 * transaction so `items` and `total` reflect the same snapshot — no SELECT/COUNT
 * skew under concurrent writes — while still handling pages past the end.
 */
export function readPage<T>(
  p: Pagination,
  select: (tx: Tx) => Promise<T[]>,
  countRows: (tx: Tx) => Promise<number>,
): Promise<Page<T>> {
  return db.transaction(
    async (tx) => {
      const items = await select(tx);
      const total = await countRows(tx);
      return page(items, p, total);
    },
    { isolationLevel: 'repeatable read', accessMode: 'read only' },
  );
}
