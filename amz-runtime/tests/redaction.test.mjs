import test from 'node:test';
import assert from 'node:assert/strict';
import { RedactedLines } from '../runtime/launcher.mjs';

test('redacts credentials split across chunks and drops bounded partial output', async () => {
  const secret = 'synthetic-runtime-password-0123456789';
  const stream = new RedactedLines([secret]);
  let output = '';
  stream.on('data', chunk => { output += chunk.toString(); });
  stream.write('Password: ' + secret.slice(0, 12));
  stream.write(secret.slice(12) + '\nBearer unknown-token\n');
  stream.write('x'.repeat(65537));
  stream.end('safe final line');
  await new Promise(resolve => stream.on('end', resolve));
  assert.ok(!output.includes(secret));
  assert.ok(!output.includes('unknown-token'));
  assert.ok(output.includes('[runtime output omitted]'));
  assert.ok(output.endsWith('safe final line'));
});
