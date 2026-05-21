import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import Result "mo:base/Result";
import Json "mo:json";
import Map "mo:map/Map";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";

import ToolContext "ToolContext";

module {

  public func config() : McpTypes.Tool = {
    name = "update_labels";
    title = ?"Update Labels";
    description = ?"Update the labels on an existing secret without changing its value. Replaces all existing labels with the provided set.";
    payment = null;
    inputSchema = Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("key", Json.obj([
          ("type", Json.str("string")),
          ("description", Json.str("The secret key to update labels for")),
        ])),
        ("labels", Json.obj([
          ("type", Json.str("array")),
          ("description", Json.str("New labels to set (replaces existing labels, max 10, each max 64 chars)")),
          ("items", Json.obj([("type", Json.str("string"))])),
          ("maxItems", #number(#int(10))),
        ])),
      ])),
      ("required", Json.arr([Json.str("key"), Json.str("labels")])),
    ]);
    outputSchema = ?Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("key", Json.obj([("type", Json.str("string"))])),
        ("labels", Json.obj([
          ("type", Json.str("array")),
          ("items", Json.obj([("type", Json.str("string"))])),
        ])),
        ("updated_at", Json.obj([("type", Json.str("number"))])),
      ])),
      ("required", Json.arr([Json.str("key"), Json.str("labels"), Json.str("updated_at")])),
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

      // Parse labels
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
        case (null) {
          return ToolContext.makeError("INVALID_INPUT: 'labels' array is required", cb);
        };
      };

      // Validate labels
      if (not ToolContext.areValidLabels(labels)) {
        return ToolContext.makeError("INVALID_INPUT: Max 10 labels, each max 64 chars", cb);
      };

      let principalMap = switch (Map.get(context.secrets, Map.phash, caller)) {
        case (?m) { m };
        case (null) {
          return ToolContext.makeError("NOT_FOUND: No secret found with key '" # key # "'", cb);
        };
      };

      let existing = switch (Map.get(principalMap, Map.thash, key)) {
        case (?s) { s };
        case (null) {
          return ToolContext.makeError("NOT_FOUND: No secret found with key '" # key # "'", cb);
        };
      };

      let now = ToolContext.now();
      let updated : ToolContext.Secret = {
        key = existing.key;
        value = existing.value;
        encrypted = existing.encrypted;
        labels = labels;
        created_at = existing.created_at;
        updated_at = now;
      };

      ignore Map.put(principalMap, Map.thash, key, updated);

      let labelsJson = Json.arr(
        Array.map<Text, Json.Json>(labels, func(l : Text) : Json.Json { Json.str(l) })
      );

      ToolContext.makeSuccess(
        Json.obj([
          ("key", Json.str(key)),
          ("labels", labelsJson),
          ("updated_at", #number(#int(now))),
        ]),
        cb,
      );
    };
  };
};