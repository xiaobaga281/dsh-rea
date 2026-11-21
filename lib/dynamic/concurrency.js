/**
 * A tiny semaphore for read-only REA calls.
 *
 * 1.4.0 marked 157 tools concurrency-safe, but the child multiplexes every
 * response over one framed stdout channel with a bounded buffer. Without a
 * gate a single model turn can enqueue dozens of large decompiler responses
 * at once. This keeps the parallelism useful and the buffer predictable.
 *
 * @module dsh-rea/lib/concurrency
 */
export function createLimiter(max = 6) {
  const limit = Number.isFinite(max) ? Math.min(Math.max(Math.floor(max), 1), 64) : 6;
  let active = 0;
  const queue = [];

  const drain = () => {
    while (active < limit && queue.length > 0) {
      const job = queue.shift();
      active += 1;
      Promise.resolve()
        .then(job.fn)
        .then(job.resolve, job.reject)
        .finally(() => { active -= 1; drain(); });
    }
  };

  return {
    limit,
    get active() { return active; },
    get queued() { return queue.length; },
    run(fn) {
      return new Promise((resolve, reject) => {
        queue.push({ fn, resolve, reject });
        drain();
      });
    },
  };
}
