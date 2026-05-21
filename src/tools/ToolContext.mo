import Principal "mo:base/Principal";
import Result "mo:base/Result";
import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import Json "mo:json";
import Map "mo:map/Map";
import Time "mo:base/Time";
import Int "mo:base/Int";

module ToolContext {

  // --- Secret type ---
  public type Secret = {
    key : Text;
    value : Text;
    encrypted : Bool;
    labels : [Text];
    created_at : Nat;
    updated_at : Nat;
  };

  // --- Storage type: Principal -> (Key -> Secret) ---
  public type SecretsStore = Map.Map<Principal, Map.Map<Text, Secret>>;

  /// Context shared between tools and the main canister
  public type ToolContext = {
    canisterPrincipal : Principal;
    owner : Principal;
    appContext : McpTypes.AppContext;
    secrets : SecretsStore;
  };

  // --- Constants ---
  public let MAX_KEY_LENGTH : Nat = 128;
  public let MAX_VALUE_SIZE : Nat = 10_240; // 10KB
  public let MAX_SECRETS_PER_PRINCIPAL : Nat = 1_000;
  public let MAX_LABELS_PER_SECRET : Nat = 10;
  public let MAX_LABEL_LENGTH : Nat = 64;

  // --- Helpers ---

  public func now() : Nat {
    Int.abs(Time.now());
  };

  /// Validate a secret key format: alphanumeric + _ - . , 1-128 chars
  public func isValidKey(key : Text) : Bool {
    let len = key.size();
    if (len == 0 or len > MAX_KEY_LENGTH) return false;
    for (c in key.chars()) {
      let valid = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '_' or c == '-' or c == '.';
      if (not valid) return false;
    };
    true;
  };

  /// Validate labels
  public func areValidLabels(labels : [Text]) : Bool {
    if (labels.size() > MAX_LABELS_PER_SECRET) return false;
    for (lbl in labels.vals()) {
      if (lbl.size() == 0 or lbl.size() > MAX_LABEL_LENGTH) return false;
    };
    true;
  };

  /// Extract caller principal from auth info
  public func getCallerPrincipal(auth : ?AuthTypes.AuthInfo) : ?Principal {
    switch (auth) {
      case (?a) { ?a.principal };
      case (null) { null };
    };
  };

  /// Get or create a principal's secret map
  public func getOrCreatePrincipalMap(store : SecretsStore, principal : Principal) : Map.Map<Text, Secret> {
    switch (Map.get(store, Map.phash, principal)) {
      case (?m) { m };
      case (null) {
        let m = Map.new<Text, Secret>();
        ignore Map.put(store, Map.phash, principal, m);
        m;
      };
    };
  };

  /// Count secrets for a principal
  public func countSecrets(store : SecretsStore, principal : Principal) : Nat {
    switch (Map.get(store, Map.phash, principal)) {
      case (?m) { Map.size(m) };
      case (null) { 0 };
    };
  };

  /// Helper function to create an error response
  public func makeError(message : Text, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) {
    cb(#ok({ content = [#text({ text = "Error: " # message })]; isError = true; structuredContent = null }));
  };

  /// Helper function to create a success response with structured JSON
  public func makeSuccess(structured : Json.Json, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) {
    cb(#ok({ content = [#text({ text = Json.stringify(structured, null) })]; isError = false; structuredContent = ?structured }));
  };

  /// Helper to require auth and extract principal
  public func requireAuth(auth : ?AuthTypes.AuthInfo, cb : (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ()) : ?Principal {
    switch (getCallerPrincipal(auth)) {
      case (?p) {
        if (Principal.isAnonymous(p)) {
          makeError("UNAUTHORIZED: Authentication required. Anonymous callers cannot access secrets.", cb);
          null;
        } else {
          ?p;
        };
      };
      case (null) {
        makeError("UNAUTHORIZED: Authentication required. Please authenticate to access secrets.", cb);
        null;
      };
    };
  };
};