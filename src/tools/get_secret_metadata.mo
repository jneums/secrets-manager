import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import Result "mo:base/Result";
import Json "mo:json";
import Map "mo:map/Map";
import Array "mo:base/Array";

import ToolContext "ToolContext";

module {

  public func config() : McpTypes.Tool = {
    name = "get_secret_metadata";
    title = ?"Get Secret Metadata";
    description = ?"Get metadata for a secret without retrieving its value. Useful for checking if a secret exists, when it was last updated, and its labels.";
    payment = null;
    inputSchema = Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("key", Json.obj([
          ("type", Json.str("string")),
          ("description", Json.str("The secret key to inspect")),
        ])),
      ])),
      ("required", Json.arr([Json.str("key")])),
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
      ])),
      ("required", Json.arr([Json.str("key")])),
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

      let labelsJson = Json.arr(
        Array.map<Text, Json.Json>(secret.labels, func(l : Text) : Json.Json { Json.str(l) })
      );

      ToolContext.makeSuccess(
        Json.obj([
          ("key", Json.str(secret.key)),
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