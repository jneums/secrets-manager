import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import Result "mo:base/Result";
import Json "mo:json";
import Map "mo:map/Map";
import Array "mo:base/Array";
import Text "mo:base/Text";

import ToolContext "ToolContext";
import Encryption "../Encryption";

module {

  public func config() : McpTypes.Tool = {
    name = "get_secret";
    title = ?"Get Secret";
    description = ?"Retrieve a secret by key. Returns the full value. If the secret was stored with encrypted=true, the returned value is the ciphertext — decrypt it client-side.";
    payment = null;
    inputSchema = Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("key", Json.obj([
          ("type", Json.str("string")),
          ("description", Json.str("The secret key to retrieve")),
        ])),
      ])),
      ("required", Json.arr([Json.str("key")])),
    ]);
    outputSchema = ?Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("key", Json.obj([("type", Json.str("string"))])),
        ("value", Json.obj([("type", Json.str("string"))])),
        ("encrypted", Json.obj([("type", Json.str("boolean"))])),
        ("labels", Json.obj([
          ("type", Json.str("array")),
          ("items", Json.obj([("type", Json.str("string"))])),
        ])),
        ("created_at", Json.obj([("type", Json.str("number"))])),
        ("updated_at", Json.obj([("type", Json.str("number"))])),
      ])),
      ("required", Json.arr([Json.str("key"), Json.str("value")])),
    ]);
  };

  public func handle(context : ToolContext.ToolContext) : McpTypes.ToolFn {
    func(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) : async () {

      let caller = switch (ToolContext.requireAuth(auth, cb)) {
        case (?p) { p };
        case (null) { return };
      };

      let key = switch (Result.toOption(Json.getAsText(args, "key"))) {
        case (?k) { k };
        case (null) {
          return ToolContext.makeError("INVALID_INPUT: 'key' is required", cb);
        };
      };

      let principalMap = switch (Map.get(context.secrets, Map.phash, caller)) {
        case (?m) { m };
        case (null) {
          return ToolContext.makeError("NOT_FOUND: No secret found with key '" # key # "'", cb);
        };
      };

      let secret = switch (Map.get(principalMap, Map.thash, key)) {
        case (?s) { s };
        case (null) {
          return ToolContext.makeError("NOT_FOUND: No secret found with key '" # key # "'", cb);
        };
      };

      // Decrypt the value
      let value = if (context.encryptionEnabled()) {
        let derivedKey = await Encryption.deriveKeyForPrincipal(caller, context.vetKdKeyId);
        switch (Encryption.decrypt(secret.ciphertext, key, derivedKey)) {
          case (?v) { v };
          case (null) {
            return ToolContext.makeError("DECRYPTION_FAILED: Could not decrypt secret '" # key # "'", cb);
          };
        };
      } else {
        // Fallback: read plaintext blob (for local testing without vetKD)
        switch (Text.decodeUtf8(secret.ciphertext)) {
          case (?v) { v };
          case (null) {
            return ToolContext.makeError("DECRYPTION_FAILED: Could not decode secret '" # key # "'", cb);
          };
        };
      };

      let labelsJson = Json.arr(
        Array.map<Text, Json.Json>(secret.labels, func(l : Text) : Json.Json { Json.str(l) })
      );

      ToolContext.makeSuccess(
        Json.obj([
          ("key", Json.str(secret.key)),
          ("value", Json.str(value)),
          ("encrypted", Json.bool(secret.clientEncrypted)),
          ("labels", labelsJson),
          ("created_at", #number(#int(secret.created_at))),
          ("updated_at", #number(#int(secret.updated_at))),
        ]),
        cb,
      );
    };
  };
};