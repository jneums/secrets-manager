import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import Result "mo:base/Result";
import Json "mo:json";
import Map "mo:map/Map";

import ToolContext "ToolContext";

module {

  public func config() : McpTypes.Tool = {
    name = "delete_secret";
    title = ?"Delete Secret";
    description = ?"Permanently delete a secret by key. This is idempotent — deleting a non-existent key returns deleted=false without error.";
    payment = null;
    inputSchema = Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("key", Json.obj([
          ("type", Json.str("string")),
          ("description", Json.str("The secret key to delete")),
        ])),
      ])),
      ("required", Json.arr([Json.str("key")])),
    ]);
    outputSchema = ?Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("key", Json.obj([("type", Json.str("string"))])),
        ("deleted", Json.obj([("type", Json.str("boolean"))])),
      ])),
      ("required", Json.arr([Json.str("key"), Json.str("deleted")])),
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
          // No secrets for this principal — idempotent, return deleted=false
          return ToolContext.makeSuccess(
            Json.obj([
              ("key", Json.str(key)),
              ("deleted", Json.bool(false)),
            ]),
            cb,
          );
        };
      };

      let removed = Map.remove(principalMap, Map.thash, key);
      let deleted = switch (removed) {
        case (?_) { true };
        case (null) { false };
      };

      ToolContext.makeSuccess(
        Json.obj([
          ("key", Json.str(key)),
          ("deleted", Json.bool(deleted)),
        ]),
        cb,
      );
    };
  };
};