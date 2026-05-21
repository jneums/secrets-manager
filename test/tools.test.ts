/**
 * Secrets Manager Tool Tests
 *
 * Tests all 6 tools: set_secret, get_secret, list_secrets, delete_secret, get_secret_metadata, update_labels
 * Tests auth requirements and principal isolation.
 */

import { describe, beforeAll, afterAll, it, expect, inject } from 'vitest';
import { PocketIc, createIdentity } from '@dfinity/pic';
import { IDL } from '@icp-sdk/core/candid';
import { AnonymousIdentity } from '@icp-sdk/core/agent';
import { idlFactory as mcpServerIdlFactory } from '../.dfx/local/canisters/secrets-manager/service.did.js';
import type { _SERVICE as McpServerService } from '../.dfx/local/canisters/secrets-manager/service.did.d.ts';
import type { Actor } from '@dfinity/pic';
import path from 'node:path';

const MCP_SERVER_WASM_PATH = path.resolve(
  __dirname,
  '../.dfx/local/canisters/secrets-manager/secrets-manager.wasm',
);

// Helper to make an MCP tool call with optional API key
async function callTool(
  actor: Actor<McpServerService>,
  toolName: string,
  args: Record<string, any>,
  apiKey?: string,
  id: string = 'test-' + toolName,
) {
  const rpcPayload = {
    jsonrpc: '2.0',
    method: 'tools/call',
    params: { name: toolName, arguments: args },
    id,
  };
  const body = new TextEncoder().encode(JSON.stringify(rpcPayload));
  const headers: [string, string][] = [['Content-Type', 'application/json']];
  if (apiKey) {
    headers.push(['X-API-Key', apiKey]);
  }
  const httpResponse = await actor.http_request_update({
    method: 'POST',
    url: '/mcp',
    headers,
    body,
    certificate_version: [],
  });
  if (httpResponse.status_code !== 200) {
    const bodyText = new TextDecoder().decode(httpResponse.body as Uint8Array);
    return {
      _status: httpResponse.status_code,
      _body: bodyText,
      result: {
        isError: true,
        content: [{ text: `HTTP ${httpResponse.status_code}: ${bodyText}` }],
      },
    };
  }
  const responseBody = JSON.parse(
    new TextDecoder().decode(httpResponse.body as Uint8Array),
  );
  return responseBody;
}

// Helper to parse the tool result text as JSON
function parseResult(response: any): any {
  const text = response.result.content[0].text;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

describe('Secrets Manager Tools', () => {
  let pic: PocketIc;
  let serverActor: Actor<McpServerService>;
  let canisterId: any;
  let testOwner = createIdentity('test-owner');
  let testUser1 = createIdentity('test-user-1');
  let testUser2 = createIdentity('test-user-2');
  let user1ApiKey: string;
  let user2ApiKey: string;

  beforeAll(async () => {
    const picUrl = inject('PIC_URL');
    pic = await PocketIc.create(picUrl);
    canisterId = await pic.createCanister();

    const initArg = IDL.encode(
      [IDL.Opt(IDL.Record({ owner: IDL.Opt(IDL.Principal) }))],
      [[{ owner: [testOwner.getPrincipal()] }]],
    );

    await pic.installCode({
      canisterId,
      wasm: MCP_SERVER_WASM_PATH,
      arg: initArg.buffer as ArrayBufferLike,
    });

    serverActor = pic.createActor<McpServerService>(
      mcpServerIdlFactory,
      canisterId,
    );

    // Disable vetKD encryption for PocketIc tests (no vetKD available locally)
    serverActor.setIdentity(testOwner);
    await serverActor.set_encryption_enabled(false);

    // Create API keys for both test users
    serverActor.setIdentity(testUser1);
    user1ApiKey = await serverActor.create_my_api_key('user1-key', ['openid']);

    serverActor.setIdentity(testUser2);
    user2ApiKey = await serverActor.create_my_api_key('user2-key', ['openid']);
  });

  afterAll(async () => {
    await pic?.tearDown();
  });

  // ==================== AUTH TESTS ====================

  describe('Authentication', () => {
    it('should reject unauthenticated callers for set_secret', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const response = await callTool(serverActor, 'set_secret', {
        key: 'test_key',
        value: 'test_value',
      });
      // Should get 401 or tool-level error
      expect(response._status === 401 || response.result.isError).toBe(true);
    });

    it('should reject unauthenticated callers for get_secret', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const response = await callTool(serverActor, 'get_secret', { key: 'test_key' });
      expect(response._status === 401 || response.result.isError).toBe(true);
    });

    it('should reject unauthenticated callers for list_secrets', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const response = await callTool(serverActor, 'list_secrets', {});
      expect(response._status === 401 || response.result.isError).toBe(true);
    });

    it('should reject unauthenticated callers for delete_secret', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const response = await callTool(serverActor, 'delete_secret', { key: 'test_key' });
      expect(response._status === 401 || response.result.isError).toBe(true);
    });

    it('should reject unauthenticated callers for get_secret_metadata', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const response = await callTool(serverActor, 'get_secret_metadata', { key: 'test_key' });
      expect(response._status === 401 || response.result.isError).toBe(true);
    });

    it('should reject unauthenticated callers for update_labels', async () => {
      serverActor.setIdentity(new AnonymousIdentity());
      const response = await callTool(serverActor, 'update_labels', {
        key: 'test_key',
        labels: ['test'],
      });
      expect(response._status === 401 || response.result.isError).toBe(true);
    });
  });

  // ==================== SET SECRET ====================

  describe('set_secret', () => {
    it('should create a new secret', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'set_secret',
        { key: 'API_KEY', value: 'sk-test-12345', labels: ['production', 'ai'] },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.key).toBe('API_KEY');
      expect(result.status).toBe('created');
      expect(result.labels).toEqual(['production', 'ai']);
      expect(result.created_at).toBeGreaterThan(0);
      expect(result.updated_at).toBeGreaterThan(0);
    });

    it('should update an existing secret', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'set_secret',
        { key: 'API_KEY', value: 'sk-test-67890-updated' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.key).toBe('API_KEY');
      expect(result.status).toBe('updated');
    });

    it('should create a second secret with labels', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'set_secret',
        {
          key: 'ANOTHER_SECRET',
          value: 'another-secret-value',
          labels: ['database'],
        },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.status).toBe('created');
    });

    it('should reject invalid key format', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'set_secret',
        { key: 'invalid key with spaces!', value: 'test' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('INVALID_INPUT');
    });

    it('should reject empty key', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'set_secret',
        { key: '', value: 'test' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('INVALID_INPUT');
    });

    it('should reject missing key', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'set_secret',
        { value: 'test' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('INVALID_INPUT');
    });

    it('should reject missing value', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'set_secret',
        { key: 'test_key' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('INVALID_INPUT');
    });
  });

  // ==================== GET SECRET ====================

  describe('get_secret', () => {
    it('should retrieve a secret with full value', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'get_secret',
        { key: 'API_KEY' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.key).toBe('API_KEY');
      expect(result.value).toBe('sk-test-67890-updated');
    });

    it('should return NOT_FOUND for non-existent key', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'get_secret',
        { key: 'DOES_NOT_EXIST' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('NOT_FOUND');
    });

    it('should retrieve second secret', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'get_secret',
        { key: 'ANOTHER_SECRET' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.value).toBe('another-secret-value');
    });
  });

  // ==================== LIST SECRETS ====================

  describe('list_secrets', () => {
    it('should list secrets without values', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(serverActor, 'list_secrets', {}, user1ApiKey);
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.total).toBeGreaterThanOrEqual(2);
      expect(result.secrets.length).toBeGreaterThanOrEqual(2);
      // Ensure no values are returned
      for (const secret of result.secrets) {
        expect(secret.value).toBeUndefined();
        expect(secret.key).toBeDefined();
      }
    });

    it('should filter by label', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'list_secrets',
        { label: 'database' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.total).toBe(1);
      expect(result.secrets[0].key).toBe('ANOTHER_SECRET');
    });

    it('should return empty for non-matching label', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'list_secrets',
        { label: 'nonexistent-label' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.total).toBe(0);
      expect(result.secrets).toEqual([]);
    });

    it('should support pagination', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'list_secrets',
        { limit: 1, offset: 0 },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.secrets.length).toBe(1);
      expect(result.total).toBeGreaterThanOrEqual(2);
    });

    it('should return empty for new principal', async () => {
      serverActor.setIdentity(testUser2);
      const response = await callTool(serverActor, 'list_secrets', {}, user2ApiKey);
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.total).toBe(0);
      expect(result.secrets).toEqual([]);
    });
  });

  // ==================== GET SECRET METADATA ====================

  describe('get_secret_metadata', () => {
    it('should return metadata without value', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'get_secret_metadata',
        { key: 'API_KEY' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.key).toBe('API_KEY');
      expect(result.value).toBeUndefined();
      expect(result.created_at).toBeGreaterThan(0);
      expect(result.updated_at).toBeGreaterThan(0);
    });

    it('should return NOT_FOUND for non-existent key', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'get_secret_metadata',
        { key: 'NOPE' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('NOT_FOUND');
    });
  });

  // ==================== UPDATE LABELS ====================

  describe('update_labels', () => {
    it('should update labels on existing secret', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'update_labels',
        { key: 'API_KEY', labels: ['staging', 'ai'] },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.key).toBe('API_KEY');
      expect(result.labels).toEqual(['staging', 'ai']);
    });

    it('should not change the secret value when updating labels', async () => {
      serverActor.setIdentity(testUser1);
      // Get the value before
      const before = parseResult(
        await callTool(serverActor, 'get_secret', { key: 'API_KEY' }, user1ApiKey),
      );
      // Update labels
      await callTool(
        serverActor,
        'update_labels',
        { key: 'API_KEY', labels: ['new-label'] },
        user1ApiKey,
      );
      // Get the value after
      const after = parseResult(
        await callTool(serverActor, 'get_secret', { key: 'API_KEY' }, user1ApiKey),
      );
      expect(after.value).toBe(before.value);
      expect(after.labels).toEqual(['new-label']);
    });

    it('should return NOT_FOUND for non-existent key', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'update_labels',
        { key: 'NOPE', labels: ['test'] },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('NOT_FOUND');
    });
  });

  // ==================== DELETE SECRET ====================

  describe('delete_secret', () => {
    it('should delete an existing secret', async () => {
      serverActor.setIdentity(testUser1);
      // First create a secret to delete
      await callTool(
        serverActor,
        'set_secret',
        { key: 'TO_DELETE', value: 'bye' },
        user1ApiKey,
      );

      const response = await callTool(
        serverActor,
        'delete_secret',
        { key: 'TO_DELETE' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.key).toBe('TO_DELETE');
      expect(result.deleted).toBe(true);
    });

    it('should return deleted=false for non-existent key (idempotent)', async () => {
      serverActor.setIdentity(testUser1);
      const response = await callTool(
        serverActor,
        'delete_secret',
        { key: 'NEVER_EXISTED' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.deleted).toBe(false);
    });

    it('should not be retrievable after deletion', async () => {
      serverActor.setIdentity(testUser1);
      await callTool(
        serverActor,
        'set_secret',
        { key: 'TEMP', value: 'temp' },
        user1ApiKey,
      );
      await callTool(serverActor, 'delete_secret', { key: 'TEMP' }, user1ApiKey);

      const response = await callTool(
        serverActor,
        'get_secret',
        { key: 'TEMP' },
        user1ApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('NOT_FOUND');
    });
  });

  // ==================== PRINCIPAL ISOLATION ====================

  describe('Principal Isolation', () => {
    it('user2 cannot see user1 secrets', async () => {
      // User1 has secrets
      serverActor.setIdentity(testUser1);
      const list1 = parseResult(
        await callTool(serverActor, 'list_secrets', {}, user1ApiKey),
      );
      expect(list1.total).toBeGreaterThan(0);

      // User2 should see nothing
      serverActor.setIdentity(testUser2);
      const list2 = parseResult(
        await callTool(serverActor, 'list_secrets', {}, user2ApiKey),
      );
      expect(list2.total).toBe(0);
    });

    it('user2 cannot get user1 secret by key', async () => {
      serverActor.setIdentity(testUser2);
      const response = await callTool(
        serverActor,
        'get_secret',
        { key: 'API_KEY' },
        user2ApiKey,
      );
      expect(response.result.isError).toBe(true);
      expect(response.result.content[0].text).toContain('NOT_FOUND');
    });

    it('user2 can create their own secrets independently', async () => {
      serverActor.setIdentity(testUser2);
      const response = await callTool(
        serverActor,
        'set_secret',
        { key: 'USER2_SECRET', value: 'user2-value' },
        user2ApiKey,
      );
      expect(response.result.isError).toBe(false);
      const result = parseResult(response);
      expect(result.status).toBe('created');

      // User2 can see their own
      const list = parseResult(
        await callTool(serverActor, 'list_secrets', {}, user2ApiKey),
      );
      expect(list.total).toBe(1);
      expect(list.secrets[0].key).toBe('USER2_SECRET');
    });
  });

  // ==================== TOOLS LIST ====================

  describe('tools/list', () => {
    it('should list all 6 tools', async () => {
      serverActor.setIdentity(testUser1);
      const rpcPayload = {
        jsonrpc: '2.0',
        method: 'tools/list',
        params: {},
        id: 'test-list-tools',
      };
      const body = new TextEncoder().encode(JSON.stringify(rpcPayload));
      const httpResponse = await actor_tools_list(serverActor, body, user1ApiKey);

      const toolNames = httpResponse.result.tools.map((t: any) => t.name);
      expect(toolNames).toContain('set_secret');
      expect(toolNames).toContain('get_secret');
      expect(toolNames).toContain('list_secrets');
      expect(toolNames).toContain('delete_secret');
      expect(toolNames).toContain('get_secret_metadata');
      expect(toolNames).toContain('update_labels');
      expect(toolNames.length).toBe(6);
    });
  });
});

// Helper for tools/list which goes through http_request (query) not update
async function actor_tools_list(
  actor: Actor<any>,
  body: Uint8Array,
  apiKey: string,
) {
  const headers: [string, string][] = [
    ['Content-Type', 'application/json'],
    ['X-API-Key', apiKey],
  ];
  // tools/list is a query, needs upgrade to update for POST
  const httpResponse = await actor.http_request_update({
    method: 'POST',
    url: '/mcp',
    headers,
    body,
    certificate_version: [],
  });
  expect(httpResponse.status_code).toBe(200);
  return JSON.parse(new TextDecoder().decode(httpResponse.body as Uint8Array));
}