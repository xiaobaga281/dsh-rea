import assert from 'node:assert/strict';
import test from 'node:test';

import { LineFramer } from '../lib/mcp-client.js';

function collect() {
  const lines = [];
  const framer = new LineFramer((line) => lines.push(line));
  return { lines, framer };
}

test('splits several messages arriving in one chunk', () => {
  const { lines, framer } = collect();
  framer.push('{"a":1}\n{"b":2}\n');
  assert.deepEqual(lines, ['{"a":1}', '{"b":2}']);
});

test('holds a partial line until its newline arrives', () => {
  const { lines, framer } = collect();
  framer.push('{"a":');
  assert.deepEqual(lines, []);
  framer.push('1}\n');
  assert.deepEqual(lines, ['{"a":1}']);
});

test('tolerates CRLF and blank lines', () => {
  const { lines, framer } = collect();
  framer.push('{"a":1}\r\n\n\r\n{"b":2}\r\n');
  assert.deepEqual(lines, ['{"a":1}', '{"b":2}']);
});

test('reassembles a message split at an arbitrary byte', () => {
  const { lines, framer } = collect();
  const message = JSON.stringify({ jsonrpc: '2.0', id: 7, result: { tools: [] } });
  for (const character of message) framer.push(character);
  framer.push('\n');
  assert.deepEqual(lines, [message]);
});

test('drops an oversized unterminated line instead of growing forever', () => {
  const dropped = [];
  const lines = [];
  const framer = new LineFramer((line) => lines.push(line), { maxLineChars: 32, onOverflow: (bytes) => dropped.push(bytes) });
  framer.push('x'.repeat(64));
  assert.equal(dropped.length, 1);
  assert.ok(dropped[0] >= 64);
  framer.push('{"ok":true}\n');
  assert.deepEqual(lines, ['{"ok":true}']);
});
