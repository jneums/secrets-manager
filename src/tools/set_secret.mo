import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import Result "mo:base/Result";
import Json "mo:json";
import Map "mo:map/Map";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import Text "mo:base/Text";

import ToolContext "ToolContext";
import Encryption "../Encryption";

module {

  public func config() : McpTypes.Tool = {
    name = "set_secret";
    title = ?"Set Secret";
    description = ?"Store or update a named secret. Values are stored per-principal. Use encrypted=true if you've encrypted the value client-side. This is an upsert — if the key exists, the value is updated.";
    payment = null;
    inputSchema = Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("key", Json.obj([
          ("type", Json.str("string")),
          ("description", Json.str("Secret name (1-128 chars, alphanumeric/underscore/hyphen/dot)")),
          ("minLength", #number(#int(1))),
          ("maxLength", #number(#int(128))),
        ])),
        ("value", Json.obj([
          ("type", Json.str("string")),
          ("description", Json.str("Secret value (max 10KB). If encrypted=true, this should be the ciphertext.")),
        ])),
        ("encrypted", Json.obj([
          ("type", Json.str("boolean")),
          ("description", Json.str("Set to true if the value is client-side encrypted (default: false)")),
        ])),
        ("labels", Json.obj([
          ("type", Json.str("array")),
          ("description", Json.str("Optional labels for organizing secrets (max 10, each max 64 chars)")),
          ("items", Json.obj([("type", Json.str("string"))])),
          ("maxItems", #number(#int(10))),
        ])),
      ])),
      ("required", Json.arr([Json.str("key"), Json.str("value")])),
    ]);
    outputSchema = ?Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("key", Json.obj([("type", Json.str("string"))])),
        ("encrypted", Json.obj([("type", Json.str("boolean"))])),
        ("labels", Json.obj([
          ("type", Json.str("array")),
          ("items", Json.obj([("type", Json.str("string"))])),
        ])),
        ("created_at", Json.obj([("type", Json.str("number"))])),
        ("updated_at", Json.obj([("type", Json.str("number"))])),
        ("status", Json.obj([
          ("type", Json.str("string")),
          ("enum", Json.arr([Json.str("created"), Json.str("updated")])),
        ])),
      ])),
      ("required", Json.arr([Json.str("key"), Json.str("status")])),
    ]);
  };

  public func handle(context : ToolContext.ToolContext) : McpTypes.ToolFn {
    func(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) : async () {

      // Require auth
      let caller = switch (ToolContext.requireAuth(auth, cb)) {
        case (?p) { p };
        case (null) { return };
      };

      // Parse key
      let key = switch (Result.toOption(Json.getAsText(args, "key"))) {
        case (?k) { k };
        case (null) {
          return ToolContext.makeError("INVALID_INPUT: 'key' is required", cb);
        };
      };

      // Validate key
      if (not ToolContext.isValidKey(key)) {
        return ToolContext.makeError("INVALID_INPUT: Key must be 1-128 chars, alphanumeric/underscore/hyphen/dot only", cb);
      };

      // Parse value
      let value = switch (Result.toOption(Json.getAsText(args, "value"))) {
        case (?v) { v };
        case (null) {
          return ToolContext.makeError("INVALID_INPUT: 'value' is required", cb);
        };
      };

      // Validate value size
      if (value.size() > ToolContext.MAX_VALUE_SIZE) {
        return ToolContext.makeError("INVALID_INPUT: Value exceeds maximum size of 10KB", cb);
      };

      // Parse encrypted flag (default false) — indicates client-side encryption
      let clientEncrypted = switch (Result.toOption(Json.getAsBool(args, "encrypted"))) {
        case (?e) { e };
        case (null) { false };
      };

      // Parse labels (default empty)
      let labels : [Text] = switch (Result.toOption(Json.getAsArray(args, "labels"))) {
        case (?arr) {
          let buf = Buffer.Buffer<Text>(arr.size());
          for (item in arr.vals()) {
            switch (item) {
              case (#string(t)) { buf.add(t) };
              case (_) {};
            };
          };
          Buffer.toArray(buf);
        };
        case (null) { [] };
      };

      // Validate labels
      if (not ToolContext.areValidLabels(labels)) {
        return ToolContext.makeError("INVALID_INPUT: Max 10 labels, each max 64 chars", cb);
      };

      // Get or create principal's map
      let principalMap = ToolContext.getOrCreatePrincipalMap(context.secrets, caller);

      // Check if key exists (for status)
      let existing = Map.get(principalMap, Map.thash, key);
      let status = switch (existing) {
        case (?_) { "updated" };
        case (null) {
          // Check limit
          if (ToolContext.countSecrets(context.secrets, caller) >= ToolContext.MAX_SECRETS_PER_PRINCIPAL) {
            return ToolContext.makeError("LIMIT_EXCEEDED: Maximum of 1000 secrets per principal reached", cb);
          };
          "created";
        };
      };

      // Encrypt the value (vetKD encryption at rest)
      let ciphertext = if (context.encryptionEnabled()) {
        let derivedKey = await Encryption.deriveKeyForPrincipal(caller, context.vetKdKeyId);
        Encryption.encrypt(value, key, derivedKey);
      } else {
        // Fallback: store as plaintext blob (for local testing without vetKD)
        Text.encodeUtf8(value);
      };

      let now = ToolContext.now();
      let created = switch (existing) {
        case (?e) { e.created_at };
        case (null) { now };
      };

      let secret : ToolContext.Secret = {
        key = key;
        ciphertext = ciphertext;
        clientEncrypted = clientEncrypted;
        labels = labels;
        created_at = created;
        updated_at = now;
      };

      ignore Map.put(principalMap, Map.thash, key, secret);

      let labelsJson = Json.arr(
        Array.map<Text, Json.Json>(labels, func(l : Text) : Json.Json { Json.str(l) })
      );

      ToolContext.makeSuccess(
        Json.obj([
          ("key", Json.str(key)),
          ("encrypted", Json.bool(clientEncrypted)),
          ("labels", labelsJson),
          ("created_at", #number(#int(created))),
          ("updated_at", #number(#int(now))),
          ("status", Json.str(status)),
        ]),
        cb,
      );
    };
  };
};