import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import Result "mo:base/Result";
import Json "mo:json";
import Map "mo:map/Map";
import Nat "mo:base/Nat";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";

import ToolContext "ToolContext";

module {

  public func config() : McpTypes.Tool = {
    name = "list_secrets";
    title = ?"List Secrets";
    description = ?"List all your secret keys with metadata. Values are NEVER returned in the list — use get_secret to retrieve a specific value. Supports filtering by label and pagination.";
    payment = null;
    inputSchema = Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("label", Json.obj([
          ("type", Json.str("string")),
          ("description", Json.str("Optional: filter secrets by this label")),
        ])),
        ("limit", Json.obj([
          ("type", Json.str("number")),
          ("description", Json.str("Max results to return (default: 50, max: 200)")),
        ])),
        ("offset", Json.obj([
          ("type", Json.str("number")),
          ("description", Json.str("Number of results to skip (default: 0)")),
        ])),
      ])),
    ]);
    outputSchema = ?Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj([
        ("secrets", Json.obj([
          ("type", Json.str("array")),
          ("items", Json.obj([
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
          ])),
        ])),
        ("total", Json.obj([("type", Json.str("number"))])),
      ])),
      ("required", Json.arr([Json.str("secrets"), Json.str("total")])),
    ]);
  };

  func hasLabel(secret : ToolContext.Secret, lbl : Text) : Bool {
    for (l in secret.labels.vals()) {
      if (l == lbl) return true;
    };
    false;
  };

  public func handle(context : ToolContext.ToolContext) : McpTypes.ToolFn {
    func(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) : async () {

      let caller = switch (ToolContext.requireAuth(auth, cb)) {
        case (?p) { p };
        case (null) { return };
      };

      // Parse optional label filter
      let labelFilter = Result.toOption(Json.getAsText(args, "label"));

      // Parse limit
      let limit = switch (Result.toOption(Json.getAsNat(args, "limit"))) {
        case (?n) { if (n > 200) { 200 } else if (n == 0) { 50 } else { n } };
        case (null) { 50 };
      };

      // Parse offset
      let offset = switch (Result.toOption(Json.getAsNat(args, "offset"))) {
        case (?n) { n };
        case (null) { 0 };
      };

      // Get principal's secrets
      let principalMap = switch (Map.get(context.secrets, Map.phash, caller)) {
        case (?m) { m };
        case (null) {
          // No secrets yet — return empty
          return ToolContext.makeSuccess(
            Json.obj([
              ("secrets", Json.arr([])),
              ("total", #number(#int(0))),
            ]),
            cb,
          );
        };
      };

      // Collect and filter
      let buf = Buffer.Buffer<ToolContext.Secret>(Map.size(principalMap));
      for ((_, secret) in Map.entries(principalMap)) {
        switch (labelFilter) {
          case (?lbl) {
            if (hasLabel(secret, lbl)) { buf.add(secret) };
          };
          case (null) { buf.add(secret) };
        };
      };

      let total = buf.size();

      // Apply pagination
      let resultBuf = Buffer.Buffer<Json.Json>(Nat.min(limit, total));
      var i : Nat = 0;
      var count : Nat = 0;
      for (secret in buf.vals()) {
        if (i >= offset and count < limit) {
          let labelsJson = Json.arr(
            Array.map<Text, Json.Json>(secret.labels, func(l : Text) : Json.Json { Json.str(l) })
          );
          resultBuf.add(
            Json.obj([
              ("key", Json.str(secret.key)),
              ("encrypted", Json.bool(secret.clientEncrypted)),
              ("labels", labelsJson),
              ("created_at", #number(#int(secret.created_at))),
              ("updated_at", #number(#int(secret.updated_at))),
            ])
          );
          count += 1;
        };
        i += 1;
      };

      ToolContext.makeSuccess(
        Json.obj([
          ("secrets", Json.arr(Buffer.toArray(resultBuf))),
          ("total", #number(#int(total))),
        ]),
        cb,
      );
    };
  };
};