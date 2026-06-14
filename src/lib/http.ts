import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

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
  pagination: { limit: number; offset: number; count: number };
}

export function page<T>(items: T[], p: Pagination): Page<T> {
  return { items, pagination: { limit: p.limit, offset: p.offset, count: items.length } };
}
