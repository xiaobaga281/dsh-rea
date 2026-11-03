/**
 * A reconciliation layer over the Host's tool registry.
 *
 * The registry is keyed by public name, and `register` hands back a disposer.
 * Syncing 207 tools on every reconnect is wasteful and, worse, the earlier
 * implementation disposed the *entire* catalog before registering the new one:
 * one failure in the middle left the model with no REA tools at all, while the
 * log claimed the previous catalog was still active.
 *
 * This module keeps the live registrations, re-registers only the definitions
 * whose signature actually changed, and scopes a failure to the single tool
 * that failed. Everything else keeps working.
 *
 * @module dsh-rea/lib/registry
 */

/** The parts of a definition that change what the model sees. */
function signatureOf(definition) {
  return JSON.stringify([
    definition?.description ?? '',
    definition?.parameters ?? null,
    definition?.deferLoading === true,
  ]);
}

/**
 * @param {(definition: object) => (() => void)|undefined} register
 * @param {{ onError?: (message: string) => void }} [options]
 */
export function createToolRegistry(register, { onError } = {}) {
  /** @type {Map<string, { dispose?: () => void, signature: string, definition: object }>} */
  const live = new Map();

  return {
    get size() {
      return live.size;
    },

    names() {
      return [...live.keys()];
    },

    /**
     * Bring the registry in line with `definitions`.
     *
     * Removals happen first (their names are disjoint from the new set), then
     * each added or changed definition is registered on its own. A throw is
     * reported against that tool and the loop continues, so one malformed
     * schema cannot take the other 206 tools with it.
     */
    apply(definitions = []) {
      const next = new Map();
      for (const definition of definitions) {
        if (definition && typeof definition.name === 'string' && !next.has(definition.name)) next.set(definition.name, definition);
      }
      let added = 0;
      let updated = 0;
      let removed = 0;
      let failed = 0;

      for (const [name, entry] of [...live]) {
        if (next.has(name)) continue;
        try { entry.dispose?.(); } catch {}
        live.delete(name);
        removed += 1;
      }

      for (const [name, definition] of next) {
        const current = live.get(name);
        const signature = signatureOf(definition);
        if (current && current.signature === signature) continue;
        if (current) {
          // Dispose before re-registering rather than after: a disposer is
          // allowed to be name-keyed, and calling the old one afterwards could
          // remove the registration that just replaced it.
          try { current.dispose?.(); } catch {}
          live.delete(name);
        }
        try {
          live.set(name, { dispose: register(definition), signature, definition });
          if (current) updated += 1; else added += 1;
        } catch (error) {
          // Restore the previous definition for this one tool when it had one:
          // a rejected schema update should cost the update, not the tool.
          if (current) {
            try {
              live.set(name, { ...current, dispose: register(current.definition) });
            } catch {}
          }
          failed += 1;
          onError?.(`dsh-rea: registering ${name} failed (${error?.message ?? error}); the other tools stay registered.`);
        }
      }
      return { added, updated, removed, failed, size: live.size };
    },

    /** Drop every live registration; used when the plugin is disposed. */
    disposeAll() {
      for (const entry of live.values()) {
        try { entry.dispose?.(); } catch {}
      }
      live.clear();
    },
  };
}
