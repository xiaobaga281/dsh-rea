import assert from 'node:assert/strict';
import test from 'node:test';

import { guardRequest, readRequestJson } from '../lib/routes.js';

const post = (headers = {}, method = 'POST') => ({ method, headers });

test('a GET endpoint refuses other methods', () => {
  assert.deepEqual(guardRequest(post({}, 'POST'), 'GET'), { status: 405, error: 'method-not-allowed' });
});

test('GET needs no body headers', () => {
  assert.equal(guardRequest({ method: 'GET', headers: {} }, 'GET'), null);
});

test('a state-changing request must be JSON', () => {
  // A cross-site form cannot set this content type without a preflight.
  const rejection = guardRequest(post({ 'content-type': 'text/plain' }), 'POST');
  assert.equal(rejection.status, 415);
});

test('the JSON content type may carry a charset parameter', () => {
  assert.equal(guardRequest(post({ 'content-type': 'application/json; charset=utf-8' }), 'POST'), null);
});

test('a same-origin JSON request is allowed', () => {
  const request = post({
    'content-type': 'application/json',
    host: '127.0.0.1:8642',
    origin: 'http://127.0.0.1:8642',
    'sec-fetch-site': 'same-origin',
  });
  assert.equal(guardRequest(request, 'POST'), null);
});

test('a request from another origin is refused', () => {
  const request = post({
    'content-type': 'application/json',
    host: '127.0.0.1:8642',
    origin: 'https://evil.example',
  });
  assert.equal(guardRequest(request, 'POST').status, 403);
});

test('a cross-site fetch is refused even while the page is on a localhost origin', () => {
  const request = post({
    'content-type': 'application/json',
    host: '127.0.0.1:8642',
    origin: 'http://127.0.0.1:8642',
    'sec-fetch-site': 'cross-site',
  });
  assert.equal(guardRequest(request, 'POST').status, 403);
});

test('a client without an Origin header is allowed', () => {
  assert.equal(guardRequest(post({ 'content-type': 'application/json' }), 'POST'), null);
});

test('an opaque origin falls back to the Sec-Fetch-Site check', () => {
  // file:// pages report `null`; there is no host to compare against.
  const request = post({ 'content-type': 'application/json', host: 'h:1', origin: 'null' });
  assert.equal(guardRequest(request, 'POST'), null);
});

test('a desktop shell scheme is not compared against the Host header', () => {
  const request = post({ 'content-type': 'application/json', host: 'h:1', origin: 'app://bundle' });
  assert.equal(guardRequest(request, 'POST'), null);
});

test('an unparseable Origin is refused rather than ignored', () => {
  const request = post({ 'content-type': 'application/json', host: 'h:1', origin: 'not a url' });
  assert.equal(guardRequest(request, 'POST').status, 403);
});

function streamOf(text) {
  return {
    async *[Symbol.asyncIterator]() {
      yield Buffer.from(text, 'utf8');
    },
  };
}

test('reads a JSON object body', async () => {
  assert.deepEqual(await readRequestJson(streamOf('{"tool":"jadx"}')), { tool: 'jadx' });
});

test('an empty body is an empty object', async () => {
  assert.deepEqual(await readRequestJson(streamOf('')), {});
});

test('a malformed body is a 400, not a 500', async () => {
  await assert.rejects(readRequestJson(streamOf('{oops')), (error) => error.statusCode === 400);
});

test('an enormous body is a 413', async () => {
  await assert.rejects(readRequestJson(streamOf(`"${'x'.repeat(70 * 1024)}"`)), (error) => error.statusCode === 413);
});
