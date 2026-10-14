// Parse-only front end (plan section 5.4).
//
// typescript's createSourceFile in PARSE-ONLY mode (no type-checking, no
// program): every supported syntax form is extracted into the serializable
// ModuleIR; nothing downstream sees an AST. Unresolvable constructs are
// recorded as dynamic markers, never dropped (plan 5.5, ADR 0011). UMD
// wrappers and IIFEs are normalized to ordinary function summaries.

import * as ts from "typescript";
import { SCHEMA_VERSION } from "../index.js";
import type {
  Assignment,
  CallSite,
  ClassDecl,
  DynamicMarker,
  ExportDecl,
  FunctionSummary,
  ImportBinding,
  ImportDecl,
  ModuleFormat,
  ModuleIR,
  ParseOptions,
  TopLevelStmt,
} from "./types.js";

const CAP = 80;

function cap(text: string): string {
  const one = text.replace(/\s+/g, " ").trim();
  return one.length > CAP ? `${one.slice(0, CAP - 1)}…` : one;
}

function scriptKindOf(file: string, options: ParseOptions): ts.ScriptKind {
  if (options.scriptKind !== undefined) {
    switch (options.scriptKind) {
      case "js":
        return ts.ScriptKind.JS;
      case "jsx":
        return ts.ScriptKind.JSX;
      case "ts":
        return ts.ScriptKind.TS;
      case "tsx":
        return ts.ScriptKind.TSX;
    }
  }
  if (file.endsWith(".ts") || file.endsWith(".mts")) return ts.ScriptKind.TS;
  if (file.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (file.endsWith(".jsx")) return ts.ScriptKind.JSX;
  return ts.ScriptKind.JS;
}

function formatOf(file: string, options: ParseOptions): ModuleFormat {
  if (options.moduleFormat !== undefined) return options.moduleFormat;
  // Without a resolver decision the format defaults by extension: TS/JSX
  // modules use import/export syntax, .cjs/.cts are CommonJS by definition.
  if (file.endsWith(".mjs") || file.endsWith(".mts")) return "esm";
  if (file.endsWith(".cjs") || file.endsWith(".cts")) return "cjs";
  if (file.endsWith(".tsx") || file.endsWith(".ts") || file.endsWith(".jsx")) return "esm";
  return "unknown";
}

/** The parser version (part of the per-file IR cache key, plan 5.4). */
export function parserVersion(): string {
  return `ts${ts.version}`;
}

interface FnCtx {
  summary: FunctionSummary;
  node: ts.FunctionLikeDeclaration;
}

interface State {
  sf: ts.SourceFile;
  file: string;
  imports: ImportDecl[];
  exports: ExportDecl[];
  functions: FunctionSummary[];
  topLevel: TopLevelStmt[];
  moduleAssignments: Assignment[];
  dynamic: DynamicMarker[];
  interop: Set<string>;
  unresolvedImports: string[];
  /** Innermost enclosing function contexts (module scope = empty). */
  fnStack: FnCtx[];
  /** Object-literal base names (innermost last; "" = anonymous). */
  objectStack: string[];
  /** Class base names (innermost last). */
  classStack: string[];
  classBases: ClassDecl[];
}

function lineOf(s: State, node: ts.Node): number {
  return s.sf.getLineAndCharacterOfPosition(node.getStart()).line + 1;
}

function textOf(s: State, node: ts.Node): string {
  return cap(node.getText(s.sf) ?? "");
}

function isStringLiteral(node: ts.Node | undefined): node is ts.StringLiteral {
  return node !== undefined && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node));
}

function unwrapOptional(node: ts.Expression): ts.Expression {
  let cur: ts.Expression = node;
  while (ts.isPostfixUnaryExpression(cur) && (cur.operator as ts.SyntaxKind) === ts.SyntaxKind.QuestionDotToken) {
    cur = (cur as ts.PostfixUnaryExpression).operand;
  }
  if (ts.isPropertyAccessExpression(cur) && cur.questionDotToken !== undefined) {
    const inner = unwrapOptional(cur.expression);
    if (ts.isIdentifier(inner)) return inner;
  }
  return cur;
}

function isOptional(node: ts.Expression): boolean {
  let cur: ts.Expression = node;
  for (;;) {
    if (ts.isPostfixUnaryExpression(cur) && (cur.operator as ts.SyntaxKind) === ts.SyntaxKind.QuestionDotToken)
      return true;
    if (ts.isPropertyAccessExpression(cur) || ts.isElementAccessExpression(cur)) {
      if (cur.questionDotToken !== undefined) return true;
      const inner = unwrapOptional(cur.expression);
      if (ts.isIdentifier(inner)) return false;
      cur = inner;
      continue;
    }
    if (ts.isCallExpression(cur)) {
      cur = cur.expression;
      continue;
    }
    return false;
  }
}

function callShape(s: State, node: ts.Expression, isTagged: boolean): CallSite["shape"] {
  if (isTagged) return "tagged";
  if ((node as ts.Expression).kind === ts.SyntaxKind.SuperKeyword) return "super";
  // Check the callee's own shape BEFORE unwrapping optionals: in TS 5.6
  // `o?.m` is a PropertyAccess carrying the `?.` token (unwrapOptional would
  // collapse it to the base `o` and lose the member/optional distinction).
  if (ts.isPropertyAccessExpression(node)) return isOptional(node) ? "optional" : "member";
  if (ts.isElementAccessExpression(node)) return "computed";
  const expr = unwrapOptional(node);
  if (ts.isIdentifier(expr)) return "direct";
  if (ts.isParenthesizedExpression(expr)) return callShape(s, expr.expression, isTagged);
  return "dynamic";
}

function isFunctionLike(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessor(node) ||
    ts.isSetAccessor(node)
  );
}

function addFunction(
  s: State,
  node: ts.FunctionLikeDeclaration,
  name: string,
  opts: { top?: boolean; exported?: boolean } = {},
): FunctionSummary | null {
  if (name.length === 0) return null;
  const top = opts.top ?? s.fnStack.length === 0;
  const summary: FunctionSummary = {
    name,
    kind: functionKind(node),
    isAsync: node.modifiers?.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword) ?? false,
    isGenerator: node.asteriskToken !== undefined,
    params: node.parameters.map((p) => textOf(s, p.name)),
    returns: [],
    calls: [],
    assignments: [],
    line: lineOf(s, node),
    exported: opts.exported ?? false,
    top,
  };
  s.functions.push(summary);
  return summary;
}

function functionKind(node: ts.FunctionLikeDeclaration): FunctionSummary["kind"] {
  if (ts.isGetAccessor(node)) return "getter";
  if (ts.isSetAccessor(node)) return "setter";
  if (ts.isConstructorDeclaration(node)) return "constructor";
  if (ts.isMethodDeclaration(node)) return "method";
  if (node.asteriskToken !== undefined) return "generator";
  // async before arrow: `async (x) => {}` carries AsyncKeyword in modifiers
  if (node.modifiers?.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword)) return "async";
  if (ts.isArrowFunction(node)) return "arrow";
  return "function";
}

/** TS 5.6 keeps parenthesized expressions: `(expr)` → ParenthesizedExpression. */
function unwrapParens(node: ts.Expression): ts.Expression {
  let cur: ts.Expression = node;
  while (ts.isParenthesizedExpression(cur)) cur = cur.expression;
  return cur;
}

/** The qualified name of a member of the innermost class/object context. */
function qualifiedName(s: State, memberName: string): string {
  if (memberName.length === 0) return "";
  const cls = s.classStack[s.classStack.length - 1];
  if (cls !== undefined && cls.length > 0) return `${cls}.${memberName}`;
  const obj = s.objectStack[s.objectStack.length - 1];
  if (obj !== undefined && obj.length > 0) return `${obj}.${memberName}`;
  return memberName;
}

// --- recorders ---------------------------------------------------------------

function recordCall(
  s: State,
  node: ts.CallExpression | ts.NewExpression | ts.TaggedTemplateExpression,
  isTagged: boolean,
): void {
  let expr: ts.Expression;
  if (node.kind === ts.SyntaxKind.NewExpression) expr = (node as ts.NewExpression).expression;
  else if (node.kind === ts.SyntaxKind.TaggedTemplateExpression) expr = (node as ts.TaggedTemplateExpression).tag;
  else expr = (node as ts.CallExpression).expression;
  const shape = node.kind === ts.SyntaxKind.NewExpression ? "new" : callShape(s, expr, isTagged);
  const args = node.kind === ts.SyntaxKind.CallExpression ? [...(node.arguments ?? [])] : [];
  const site: CallSite = {
    shape,
    // `o?.m` → `o.m`: the callee is the callee expression with the
    // optional-chaining marker stripped (never the unwrapped base).
    callee: textOf(s, expr).replace(/\?\./g, "."),
    isOptional: isOptional(expr),
    args: args.slice(0, 8).map((a) => textOf(s, a as ts.Expression)),
    line: lineOf(s, node),
  };
  const ctx = s.fnStack[s.fnStack.length - 1];
  if (ctx !== undefined) ctx.summary.calls.push(site);
}

function recordDynamic(s: State, kind: DynamicMarker["kind"], node: ts.Node): void {
  const ctx = s.fnStack[s.fnStack.length - 1];
  const marker: DynamicMarker = { kind, shape: textOf(s, node), line: lineOf(s, node) };
  if (ctx !== undefined) marker.functionName = ctx.summary.name;
  s.dynamic.push(marker);
}

/** Dynamic-risk markers attached to a call (eval / require(expr) / computed). */
function dynamicForCall(s: State, node: ts.CallExpression): void {
  const expr = unwrapOptional(node.expression);
  // import("...") / import(expr)
  if ((node.expression as ts.Expression).kind === ts.SyntaxKind.ImportKeyword) {
    const arg = node.arguments[0];
    if (arg === undefined || !isStringLiteral(arg)) {
      // non-literal: dynamic marker AND unresolved (M4 decides what it reaches)
      recordDynamic(s, "import-expr", node);
      if (arg !== undefined) s.unresolvedImports.push(textOf(s, arg));
      return;
    }
    return;
  }
  if (ts.isIdentifier(expr)) {
    const name = expr.text;
    if (name === "eval") {
      recordDynamic(s, "eval", node);
      return;
    }
    if (name === "require") {
      const arg = node.arguments[0];
      if (arg === undefined || !isStringLiteral(arg)) {
        recordDynamic(s, "require-expr", node);
      }
      return;
    }
  }
  // `new Function("...")()` — the callee itself is dynamic code. Inside a
  // function body the child walk records the marker on the NewExpression
  // itself (visit), so record only at module scope (no child walk there).
  const newExpr = unwrapOptional(node.expression);
  if (s.fnStack.length === 0 && ts.isNewExpression(newExpr)) {
    const ctor = unwrapOptional(newExpr.expression);
    if (ts.isIdentifier(ctor) && ctor.text === "Function") {
      recordDynamic(s, "new-function", node);
      return;
    }
  }
  const accessed = unwrapOptional(node.expression);
  if (ts.isElementAccessExpression(accessed)) {
    const arg = accessed.argumentExpression;
    if (arg !== undefined && !isStringLiteral(arg) && !ts.isNumericLiteral(arg)) {
      recordDynamic(s, "computed-call", node);
    }
  }
}

function recordAssignment(s: State, target: ts.Expression, valueText: string, line: number): void {
  const ctx = s.fnStack[s.fnStack.length - 1];
  if (ctx === undefined) return;
  const shape = textOf(s, target);
  if (shape.length === 0) return;
  let kind: Assignment["kind"];
  if (ts.isIdentifier(unwrapOptional(target))) kind = "identifier";
  else if (shape.includes(".prototype.")) kind = "prototype";
  else kind = "member";
  ctx.summary.assignments.push({ target: shape, value: valueText, kind, line });
}

/** A declared function is called at module scope: the module-init call. */
function topLevelCallEntry(s: State, node: ts.Expression, line: number): void {
  let entry: TopLevelStmt = { kind: "expression", shape: textOf(s, node), line };
  if (ts.isCallExpression(node)) {
    const callee = unwrapOptional(node.expression);
    const fn = ts.isIdentifier(callee) ? s.functions.find((f) => f.name === callee.text) : undefined;
    entry = {
      kind: "call",
      shape: textOf(s, node),
      line,
      ...(fn !== undefined ? { functionName: fn.name } : {}),
    };
  }
  s.topLevel.push(entry);
}

// --- top-level walk ----------------------------------------------------------

/** TS 5.6: `export function f(){}`, `export default function f(){}`,
 * `export const x = ...` carry the export as a modifier on the declaration
 * (no wrapping ExportDeclaration). */
function exportKindOf(node: ts.Node): "named" | "default" | null {
  const mods = (node as { modifiers?: ts.NodeArray<ts.ModifierLike> }).modifiers ?? [];
  const exported = mods.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
  if (!exported) return null;
  if (mods.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword)) return "default";
  return "named";
}

/** `export default <expr>` (TS 5.6: ExportAssignment without export=). */
function recordDefaultExport(s: State, node: ts.ExportAssignment, line: number): void {
  const expr = node.expression;
  const rec: ExportDecl = { name: "default", kind: "default", line };
  if (ts.isIdentifier(expr)) rec.local = expr.text;
  s.exports.push(rec);
  if (isFunctionLike(expr)) {
    const fn = expr as ts.FunctionLikeDeclaration;
    const name = ts.isFunctionExpression(fn) && fn.name !== undefined ? textOf(s, fn.name) : "default";
    const summary = addFunction(s, fn, name, { top: true, exported: true });
    if (summary !== null) {
      s.fnStack.push({ summary, node: fn });
      walkBody(s, fn);
      s.fnStack.pop();
    }
    return;
  }
  if (ts.isClassExpression(expr)) {
    const name = expr.name !== undefined ? textOf(s, expr.name) : "";
    if (name.length > 0) walkClass(s, expr, name, line);
    return;
  }
  if (ts.isCallExpression(expr)) {
    dynamicForCall(s, expr);
    recordCall(s, expr, false);
    return;
  }
  s.topLevel.push({ kind: "expression", shape: textOf(s, expr), line });
}

function walkTopLevel(s: State, stmt: ts.Statement): void {
  const line = lineOf(s, stmt);

  if (ts.isExpressionStatement(stmt)) {
    walkTopLevelExpression(s, stmt.expression, line);
    return;
  }
  if (ts.isImportDeclaration(stmt)) {
    recordEsmImport(s, stmt, line);
    return;
  }
  if (ts.isExportDeclaration(stmt)) {
    recordExport(s, stmt, line);
    return;
  }
  if (ts.isExportAssignment(stmt)) {
    if (stmt.isExportEquals !== true) {
      recordDefaultExport(s, stmt, line);
      return;
    }
    // `export = X` (CJS): treated like module.exports = X
    s.exports.push({ name: "module-exports", kind: "module-exports", line });
    s.topLevel.push({ kind: "assignment", shape: textOf(s, stmt), line });
    return;
  }
  if (ts.isFunctionDeclaration(stmt)) {
    const name = stmt.name !== undefined ? textOf(s, stmt.name) : "";
    const exportKind = exportKindOf(stmt);
    const summary = addFunction(s, stmt, name, { top: true, exported: exportKind !== null });
    if (summary !== null) {
      s.fnStack.push({ summary, node: stmt });
      walkBody(s, stmt);
      s.fnStack.pop();
    }
    if (exportKind === "named" && name.length > 0) s.exports.push({ name, local: name, kind: "named", line });
    // `export default function handler(){}`: FunctionDeclaration with
    // export+default modifiers (NOT an ExportAssignment in TS 5.6).
    if (exportKind === "default" && name.length > 0)
      s.exports.push({ name: "default", local: name, kind: "default", line });
    s.topLevel.push({ kind: "other", shape: `function ${name}`, line });
    return;
  }
  if (ts.isClassDeclaration(stmt)) {
    const name = stmt.name !== undefined ? textOf(s, stmt.name) : "";
    const exportKind = exportKindOf(stmt);
    if (exportKind === "named" && name.length > 0) s.exports.push({ name, local: name, kind: "named", line });
    if (exportKind === "default" && name.length > 0)
      s.exports.push({ name: "default", local: name, kind: "default", line });
    walkClass(s, stmt, name, line);
    return;
  }
  if (ts.isVariableStatement(stmt)) {
    recordTopLevelVariables(s, stmt, line, exportKindOf(stmt));
    return;
  }
  // if/for/try at module scope: executed on load, recorded (plan 5.4).
  s.topLevel.push({ kind: "other", shape: textOf(s, stmt), line });
  walkGeneric(s, stmt);
}

function walkTopLevelExpression(s: State, expr: ts.Expression, line: number): void {
  if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
    if (isExportsAssignment(expr)) {
      recordExportsAssignment(s, expr, line);
      return;
    }
    recordDynamicForTopLevel(s, expr);
    s.topLevel.push({ kind: "assignment", shape: textOf(s, expr), line });
    return;
  }
  if (ts.isCallExpression(expr)) {
    // A top-level IIFE is normalized to an ordinary function summary
    // (`(function(){...})()` — the callee may be parenthesized).
    const callee = unwrapParens(expr.expression);
    if (ts.isFunctionExpression(callee)) {
      s.interop.add("iife");
      const name = `<iife@${line}>`;
      const summary = addFunction(s, callee, name, { top: true });
      if (summary !== null) {
        s.fnStack.push({ summary, node: callee });
        walkBody(s, callee);
        s.fnStack.pop();
      }
      s.topLevel.push({ kind: "call", shape: textOf(s, expr), line });
      return;
    }
    recordDynamicForTopLevel(s, expr);
    recordDefineProperty(s, expr, line);
    if (isInteropHelperCall(s, expr)) return;
    topLevelCallEntry(s, expr, line);
    return;
  }
  if (ts.isNewExpression(expr)) {
    if (
      ts.isIdentifier(unwrapOptional(expr.expression)) &&
      (unwrapOptional(expr.expression) as ts.Identifier).text === "Function"
    ) {
      recordDynamic(s, "new-function", expr);
    }
    s.topLevel.push({ kind: "expression", shape: textOf(s, expr), line });
    return;
  }
  s.topLevel.push({ kind: "expression", shape: textOf(s, expr), line });
}

function recordDynamicForTopLevel(s: State, expr: ts.Expression): void {
  if (ts.isCallExpression(expr)) {
    dynamicForCall(s, expr);
    if ((expr.expression as ts.Expression).kind === ts.SyntaxKind.ImportKeyword) {
      const arg = expr.arguments[0];
      if (arg !== undefined && isStringLiteral(arg)) {
        s.imports.push({
          module: arg.text,
          kind: "import-dynamic",
          bindings: [],
          dynamic: true,
          line: lineOf(s, expr),
        });
        return;
      }
    }
    if (
      ts.isIdentifier(unwrapOptional(expr.expression)) &&
      (unwrapOptional(expr.expression) as ts.Identifier).text === "require"
    ) {
      const arg = expr.arguments[0];
      if (arg !== undefined && isStringLiteral(arg)) {
        s.imports.push({ module: arg.text, kind: "require", bindings: [], dynamic: false, line: lineOf(s, expr) });
      }
      return;
    }
  }
  if (ts.isNewExpression(expr) && ts.isIdentifier(unwrapOptional(expr.expression))) {
    const t = (unwrapOptional(expr.expression) as ts.Identifier).text;
    if (t === "Function") recordDynamic(s, "new-function", expr);
  }
}

/** `module.exports = ...` or `exports.x = ...` (top level). */
function isExportsAssignment(node: ts.Node): node is ts.BinaryExpression {
  if (!ts.isBinaryExpression(node) || node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return false;
  const lhs = unwrapOptional(node.left as ts.Expression);
  if (ts.isPropertyAccessExpression(lhs)) {
    const base = unwrapOptional(lhs.expression);
    return ts.isIdentifier(base) && (base.text === "module" || base.text === "exports");
  }
  return false;
}

function recordExportsAssignment(s: State, node: ts.BinaryExpression, line: number): void {
  const lhs = unwrapOptional(node.left as ts.Expression);
  const rhs = node.right as ts.Expression;
  if (ts.isPropertyAccessExpression(lhs)) {
    const base = unwrapOptional(lhs.expression);
    if (ts.isIdentifier(base) && base.text === "exports" && ts.isIdentifier(lhs.name)) {
      const name = lhs.name.text;
      if (isFunctionLike(rhs)) {
        // `exports.handler = function...` — the export's local IS the
        // function (named `name`): callback-interface detection and
        // export resolution need the local to exist.
        s.exports.push({ name, local: name, kind: "named", line });
        const summary = addFunction(s, rhs as ts.FunctionLikeDeclaration, name, { top: true, exported: true });
        if (summary !== null) {
          s.fnStack.push({ summary, node: rhs as ts.FunctionLikeDeclaration });
          walkBody(s, rhs as ts.FunctionLikeDeclaration);
          s.fnStack.pop();
        }
        return;
      }
      s.exports.push({ name, kind: "named", line });
      s.topLevel.push({ kind: "assignment", shape: textOf(s, node), line });
      return;
    }
    if (ts.isIdentifier(base) && base.text === "module" && lhs.name.text === "exports") {
      s.exports.push({ name: "module-exports", kind: "module-exports", line });
      if (ts.isObjectLiteralExpression(rhs)) {
        s.objectStack.push("");
        for (const prop of rhs.properties) {
          recordObjectMember(s, prop, line);
          const keyText = objectMemberKey(s, prop);
          if (keyText.length > 0) {
            // A member that IS (or refers to) a module function exports it:
            // `module.exports = { handler }` / `{ handler: fn }`.
            const fn = s.functions.find((f) => f.name === keyText && f.top);
            s.exports.push(
              fn !== undefined
                ? { name: keyText, local: keyText, kind: "named", line }
                : { name: keyText, kind: "named", line },
            );
          }
        }
        s.objectStack.pop();
        s.topLevel.push({ kind: "assignment", shape: textOf(s, node), line });
        return;
      }
      if (isFunctionLike(rhs)) {
        s.exports.push({ name: "default", kind: "module-exports", line });
        const summary = addFunction(s, rhs as ts.FunctionLikeDeclaration, "default", { top: true, exported: true });
        if (summary !== null) {
          s.fnStack.push({ summary, node: rhs as ts.FunctionLikeDeclaration });
          walkBody(s, rhs as ts.FunctionLikeDeclaration);
          s.fnStack.pop();
        }
        return;
      }
      s.topLevel.push({ kind: "assignment", shape: textOf(s, node), line });
      return;
    }
  }
  s.topLevel.push({ kind: "assignment", shape: textOf(s, node), line });
}

/** Object.defineProperty(exports, "name", { get() {...}, set() {...} }). */
function recordDefineProperty(s: State, node: ts.Expression, line: number): void {
  if (!ts.isCallExpression(node)) return;
  const callee = unwrapOptional(node.expression);
  if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== "defineProperty") return;
  const objBase = unwrapOptional(callee.expression);
  if (!ts.isIdentifier(objBase) || objBase.text !== "Object") return;
  const [obj, nameArg, descriptor] = [node.arguments[0], node.arguments[1], node.arguments[2]];
  if (obj === undefined || !ts.isIdentifier(obj) || obj.text !== "exports") return;
  if (nameArg === undefined || !isStringLiteral(nameArg)) return;
  if (descriptor === undefined || !ts.isObjectLiteralExpression(descriptor)) return;
  const name = nameArg.text;
  s.exports.push({ name, kind: "named", line });
  for (const prop of descriptor.properties) {
    let fn: ts.FunctionLikeDeclaration | null = null;
    let accessor = "";
    if (ts.isShorthandPropertyAssignment(prop)) continue;
    if (ts.isPropertyAssignment(prop) && isFunctionLike(prop.initializer)) {
      fn = prop.initializer as ts.FunctionLikeDeclaration;
      accessor = ts.isIdentifier(prop.name) ? prop.name.text : "";
    }
    if (fn === null) continue;
    const summary = addFunction(s, fn, name, { top: true, exported: true });
    if (summary !== null) {
      if (accessor === "get") summary.kind = "getter";
      if (accessor === "set") summary.kind = "setter";
      s.fnStack.push({ summary, node: fn });
      walkBody(s, fn);
      s.fnStack.pop();
    }
  }
}

/** TS-compiled interop helpers (__exportStar / __importDefault / __esModule). */
function isInteropHelperCall(s: State, node: ts.CallExpression): boolean {
  const callee = unwrapOptional(node.expression);
  if (!ts.isIdentifier(callee)) return false;
  if (callee.text === "__exportStar") {
    s.interop.add("exportStar");
    return true;
  }
  if (callee.text === "__importDefault") {
    s.interop.add("importDefault");
    return true;
  }
  if (callee.text === "__esModule") return true;
  return false;
}

function recordEsmImport(s: State, stmt: ts.ImportDeclaration, line: number): void {
  const clause = stmt.moduleSpecifier;
  const literal = isStringLiteral(clause) ? clause.text : null;
  const bindings: ImportBinding[] = [];
  const bind = stmt.importClause;
  if (bind !== undefined) {
    if (bind.name !== undefined) bindings.push({ local: bind.name.text, exported: "default" });
    if (bind.namedBindings !== null && bind.namedBindings !== undefined) {
      if (ts.isNamespaceImport(bind.namedBindings)) {
        // `import * as ns from "dep"`: the namespace object is the binding
        bindings.push({ local: bind.namedBindings.name.text, exported: "*" });
      } else if (ts.isNamedImports(bind.namedBindings)) {
        for (const n of bind.namedBindings.elements) {
          bindings.push({
            local: n.name.text,
            exported: n.propertyName !== undefined ? n.propertyName.text : n.name.text,
          });
        }
      }
    }
  }
  if (literal === null) s.unresolvedImports.push(textOf(s, clause));
  s.imports.push({
    module: literal ?? textOf(s, clause),
    kind: "esm",
    bindings,
    dynamic: literal === null,
    line,
  });
}

function recordExport(s: State, stmt: ts.ExportDeclaration, line: number): void {
  const from =
    stmt.moduleSpecifier !== undefined && isStringLiteral(stmt.moduleSpecifier) ? stmt.moduleSpecifier.text : undefined;

  if (stmt.moduleSpecifier !== undefined) {
    if (stmt.exportClause !== null && stmt.exportClause !== undefined && ts.isNamedExports(stmt.exportClause)) {
      for (const el of stmt.exportClause.elements) {
        const name = el.name.text;
        const local = el.propertyName !== undefined ? el.propertyName.text : name;
        const rec: ExportDecl = { name, local, kind: "named", line };
        if (from !== undefined) rec.from = from;
        s.exports.push(rec);
      }
    } else {
      const rec: ExportDecl = { name: "*", kind: "star", line };
      if (from !== undefined) rec.from = from;
      s.exports.push(rec);
    }
    // A re-export LOADS the source module at import time: link it (no local
    // bindings — the export table of the target module is the interface).
    if (from !== undefined && !s.imports.some((i) => i.kind === "esm" && i.module === from)) {
      s.imports.push({ module: from, kind: "esm", bindings: [], dynamic: false, line });
    }
    return;
  }

  if (stmt.exportClause !== null && stmt.exportClause !== undefined && ts.isNamedExports(stmt.exportClause)) {
    for (const el of stmt.exportClause.elements) {
      const name = el.name.text;
      const local = el.propertyName !== undefined ? el.propertyName.text : name;
      s.exports.push({ name, local, kind: "named", line });
      const fn = s.functions.find((f) => f.name === local || f.name === name);
      if (fn !== undefined) fn.exported = true;
    }
  }
}

function recordTopLevelVariables(
  s: State,
  stmt: ts.VariableStatement,
  line: number,
  exportKind: "named" | "default" | null,
): void {
  for (const decl of stmt.declarationList.declarations) {
    const init = decl.initializer;
    if (init === undefined) continue;
    const name = ts.isIdentifier(decl.name) ? decl.name.text : "";

    // `export const f = ...` / `export default const f = ...` (modifier form)
    const pushExport = (): void => {
      if (exportKind === "named" && name.length > 0) s.exports.push({ name, local: name, kind: "named", line });
      if (exportKind === "default" && name.length > 0)
        s.exports.push({ name: "default", local: name, kind: "default", line });
    };

    if (ts.isCallExpression(init)) {
      const callee = unwrapOptional(init.expression);
      if (ts.isIdentifier(callee) && callee.text === "require") {
        const arg = init.arguments[0];
        const literal = arg !== undefined && isStringLiteral(arg) ? arg.text : null;
        if (literal === null && arg !== undefined) s.unresolvedImports.push(textOf(s, arg));
        s.imports.push({
          module: literal ?? (arg !== undefined ? textOf(s, arg) : ""),
          kind: literal === null ? "require-dynamic" : "require",
          bindings: requireBindingsOf(decl.name, name),
          dynamic: literal === null,
          line,
        });
        s.topLevel.push({ kind: "other", shape: `require(${literal ?? "?"})`, line });
        return;
      }
      if ((init.expression as ts.Expression).kind === ts.SyntaxKind.ImportKeyword) {
        const arg = init.arguments[0];
        if (arg !== undefined && isStringLiteral(arg)) {
          s.imports.push({
            module: arg.text,
            kind: "import-dynamic",
            bindings: name.length > 0 ? [{ local: name, exported: "*" }] : [],
            dynamic: true,
            line,
          });
          return;
        }
        // `const p = import(name)`: dynamic marker AND unresolved
        recordDynamic(s, "import-expr", init);
        if (arg !== undefined) s.unresolvedImports.push(textOf(s, arg));
        return;
      }
      // Module-scope creator assignment (`const app = express()`) — recorded
      // for framework entry detection (M4); require/import inits returned above.
      if (name.length > 0) s.moduleAssignments.push({ target: name, value: textOf(s, init), kind: "identifier", line });
      recordDynamicForTopLevel(s, init);
      if (isInteropHelperCall(s, init)) {
        s.topLevel.push({ kind: "call", shape: textOf(s, init), line });
        return;
      }
      const fn = ts.isIdentifier(callee) ? s.functions.find((f) => f.name === callee.text) : undefined;
      s.topLevel.push({
        kind: "call",
        shape: textOf(s, init),
        line,
        ...(fn !== undefined ? { functionName: fn.name } : {}),
      });
      return;
    }

    if (isFunctionLike(init)) {
      if (name.length > 0) {
        const summary = addFunction(s, init as ts.FunctionLikeDeclaration, name, {
          top: true,
          exported: exportKind !== null,
        });
        if (summary !== null) {
          s.fnStack.push({ summary, node: init as ts.FunctionLikeDeclaration });
          walkBody(s, init as ts.FunctionLikeDeclaration);
          s.fnStack.pop();
        }
      }
      pushExport();
      return;
    }

    if (ts.isObjectLiteralExpression(init)) {
      s.objectStack.push(name);
      for (const prop of init.properties) recordObjectMember(s, prop, line);
      s.objectStack.pop();
      s.topLevel.push({ kind: "other", shape: `object ${name || ""}`.trim(), line });
      pushExport();
      return;
    }
    if (ts.isNewExpression(init)) {
      // `const app = new Koa()` — framework creator (M4 entry detection)
      if (name.length > 0) s.moduleAssignments.push({ target: name, value: textOf(s, init), kind: "identifier", line });
      s.topLevel.push({ kind: "other", shape: textOf(s, decl).slice(0, 60), line });
      pushExport();
      return;
    }

    s.topLevel.push({ kind: "other", shape: textOf(s, decl).slice(0, 60), line });
    pushExport();
  }
}

/**
 * Bindings of `const X = require(...)`: a plain identifier, or the names of an
 * object pattern (`const {a, b as c} = require(...)`). Array patterns are
 * positional (no names) and stay empty.
 */
function requireBindingsOf(pattern: ts.DeclarationName, plainName: string): ImportBinding[] {
  if (plainName.length > 0) return [{ local: plainName, exported: plainName }];
  if (ts.isObjectBindingPattern(pattern)) {
    const out: ImportBinding[] = [];
    for (const el of pattern.elements) {
      const local = ts.isIdentifier(el.name) ? el.name.text : "";
      if (local.length === 0) continue;
      const exported = el.propertyName !== undefined ? (el.propertyName.getText() ?? local) : local;
      out.push({ local, exported });
    }
    return out;
  }
  return [];
}

function objectMemberKey(s: State, prop: ts.ObjectLiteralElementLike): string {
  const name = prop.name;
  if (name === undefined) return "";
  if (ts.isIdentifier(name)) return name.text;
  if (ts.isStringLiteral(name)) return name.text;
  if (ts.isNumericLiteral(name)) return name.text;
  return textOf(s, name);
}

function recordObjectMember(s: State, prop: ts.ObjectLiteralElementLike, line: number): void {
  if (ts.isSpreadAssignment(prop)) return;
  const key = objectMemberKey(s, prop);
  if (key.length === 0) return;
  const qualified = qualifiedName(s, key);
  if (ts.isShorthandPropertyAssignment(prop)) return;
  if (ts.isMethodDeclaration(prop)) {
    // method shorthand: `{ run(x) {...} }`
    const summary = addFunction(s, prop, qualified, { top: s.fnStack.length === 0 });
    if (summary !== null) {
      s.fnStack.push({ summary, node: prop });
      walkBody(s, prop);
      s.fnStack.pop();
    }
    return;
  }
  if (ts.isPropertyAssignment(prop)) {
    const value = prop.initializer;
    if (isFunctionLike(value)) {
      const summary = addFunction(s, value as ts.FunctionLikeDeclaration, qualified, { top: s.fnStack.length === 0 });
      if (summary !== null) {
        s.fnStack.push({ summary, node: value as ts.FunctionLikeDeclaration });
        walkBody(s, value as ts.FunctionLikeDeclaration);
        s.fnStack.pop();
      }
      return;
    }
    if (ts.isCallExpression(value)) {
      const ctx = s.fnStack[s.fnStack.length - 1];
      const site: CallSite = {
        shape: callShape(s, value.expression, false),
        callee: textOf(s, unwrapOptional(value.expression)),
        isOptional: isOptional(value.expression),
        args: value.arguments.slice(0, 8).map((a) => textOf(s, a as ts.Expression)),
        line: lineOf(s, value),
      };
      if (ctx !== undefined) ctx.summary.calls.push(site);
      return;
    }
    return;
  }
  walkGeneric(s, prop);
}

function walkClass(s: State, cls: ts.ClassLikeDeclaration, baseName: string, line: number): void {
  s.classStack.push(baseName);
  if (baseName.length > 0) {
    // TS 5.6: `heritageClauses` (plural, an array) replaced the singular
    // `heritageClause`; take the first `extends` target (`class B extends A`).
    const heritage = (cls.heritageClauses ?? [])
      .filter((h) => h.token === ts.SyntaxKind.ExtendsKeyword)
      .map((h) => h.types[0])
      .find((t) => t !== undefined);
    const rec: ClassDecl = { name: baseName, line };
    if (heritage !== undefined) rec.base = textOf(s, heritage);
    s.classBases.push(rec);
  }
  for (const member of cls.members) {
    if (ts.isConstructorDeclaration(member)) {
      const name = baseName.length > 0 ? `${baseName}.#constructor` : "#constructor";
      const summary = addFunction(s, member, name, { top: true });
      if (summary !== null) {
        s.fnStack.push({ summary, node: member });
        walkBody(s, member);
        s.fnStack.pop();
      }
      continue;
    }
    if (ts.isMethodDeclaration(member) || ts.isGetAccessor(member) || ts.isSetAccessor(member)) {
      const memberName = member.name !== undefined ? textOf(s, member.name) : "";
      const name = qualifiedName(s, memberName);
      if (name.length > 0) {
        const summary = addFunction(s, member as ts.FunctionLikeDeclaration, name, { top: true });
        if (summary !== null) {
          s.fnStack.push({ summary, node: member as ts.FunctionLikeDeclaration });
          walkBody(s, member as ts.FunctionLikeDeclaration);
          s.fnStack.pop();
        }
      }
      continue;
    }
    if (ts.isPropertyDeclaration(member)) {
      const init = member.initializer;
      if (init !== undefined && isFunctionLike(init)) {
        const memberName = member.name !== undefined ? textOf(s, member.name) : "";
        const name = qualifiedName(s, memberName);
        if (name.length > 0) {
          const summary = addFunction(s, init as ts.FunctionLikeDeclaration, name, { top: true });
          if (summary !== null) {
            s.fnStack.push({ summary, node: init as ts.FunctionLikeDeclaration });
            walkBody(s, init as ts.FunctionLikeDeclaration);
            s.fnStack.pop();
          }
        }
      }
    }
  }
  s.classStack.pop();
  void line;
}

// --- function body walk ------------------------------------------------------

/** Walk a function body: calls, returns, assignments, nested functions, dynamics. */
function walkBody(s: State, fn: ts.FunctionLikeDeclaration): void {
  const body = fn.body;
  if (body === null || body === undefined) return;
  const visit = (node: ts.Node): void => {
    if (node === body) {
      // the body itself (a block or a single expression arrow)
    }
    if (isFunctionLike(node)) {
      const name = nameOfFunction(s, node);
      if (name.length > 0) {
        const summary = addFunction(s, node, name);
        if (summary !== null) {
          s.fnStack.push({ summary, node });
          if (node.body !== null && node.body !== undefined) walkNode(s, node.body as ts.Node, visit);
          s.fnStack.pop();
        }
      } else if (node.body !== null && node.body !== undefined) {
        walkNode(s, node.body as ts.Node, visit);
      }
      return;
    }
    if (ts.isReturnStatement(node) && node.expression !== undefined) {
      const ctx = s.fnStack[s.fnStack.length - 1];
      if (ctx !== undefined) ctx.summary.returns.push(textOf(s, node.expression as ts.Expression));
      // `return f(x);` / `return {...}`: the expression still contains
      // call sites and object members — keep walking.
      walkNode(s, node, visit);
      return;
    }
    if (ts.isCallExpression(node)) {
      dynamicForCall(s, node);
      recordCall(s, node, false);
      walkNode(s, node, visit);
      return;
    }
    if (ts.isNewExpression(node)) {
      const callee = unwrapOptional(node.expression);
      if (ts.isIdentifier(callee) && callee.text === "Function") recordDynamic(s, "new-function", node);
      recordCall(s, node, false);
      walkNode(s, node, visit);
      return;
    }
    if (ts.isTaggedTemplateExpression(node)) {
      recordCall(s, node, true);
      return;
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      recordAssignment(s, node.left as ts.Expression, textOf(s, node.right as ts.Expression), lineOf(s, node));
      // Object-literal or class on the RHS.
      if (ts.isObjectLiteralExpression(node.right)) {
        s.objectStack.push("");
        for (const prop of node.right.properties) recordObjectMember(s, prop, lineOf(s, node));
        s.objectStack.pop();
      }
      if (ts.isClassLike(node.right)) {
        const clsName = (node.right as ts.ClassLikeDeclaration).name;
        if (clsName !== undefined)
          walkClass(s, node.right as ts.ClassLikeDeclaration, textOf(s, clsName), lineOf(s, node));
      }
      walkNode(s, node, visit);
      return;
    }
    if (ts.isVariableDeclaration(node) && node.initializer !== undefined) {
      const init = node.initializer;
      const name = ts.isIdentifier(node.name) ? node.name.text : "";
      if (isFunctionLike(init)) {
        const qualified = name.length > 0 ? name : qualifiedName(s, name);
        if (qualified.length > 0) {
          const summary = addFunction(s, init as ts.FunctionLikeDeclaration, qualified);
          if (summary !== null) {
            s.fnStack.push({ summary, node: init as ts.FunctionLikeDeclaration });
            walkNode(s, init as ts.Node, visit);
            s.fnStack.pop();
          }
          return;
        }
      }
      if (ts.isObjectLiteralExpression(init)) {
        s.objectStack.push(name);
        for (const prop of init.properties) recordObjectMember(s, prop, lineOf(s, node));
        s.objectStack.pop();
        return;
      }
      if (ts.isClassLike(init)) {
        const clsName = (init as ts.ClassLikeDeclaration).name;
        const base = clsName !== undefined ? textOf(s, clsName) : name;
        if (base.length > 0) walkClass(s, init as ts.ClassLikeDeclaration, base, lineOf(s, node));
        return;
      }
      if (ts.isCallExpression(init)) {
        dynamicForCall(s, init);
        recordCall(s, init, false);
        // `const x = f()`: the call result flows into x (0-CFA return flow,
        // plan 5.5 item 3) — record it as an assignment too.
        recordAssignment(s, node.name as ts.Expression, textOf(s, init), lineOf(s, node));
        return;
      }
      if (ts.isNewExpression(init)) {
        // `const o = new C()`: receiver flow to the instantiated class (RTA,
        // plan 5.5 item 2) — record it as an assignment too. The initializer
        // IS a call site (shape "new"): record it directly — walkNode only
        // visits the initializer's children, never the node itself.
        recordAssignment(s, node.name as ts.Expression, textOf(s, init), lineOf(s, node));
        recordCall(s, init, false);
        walkNode(s, init, visit);
        return;
      }
      // Any other initializer (`const alias = handler;`, `const a = b.c;`,
      // literals) — identifier/member flow (0-CFA, plan 5.5 item 3).
      recordAssignment(s, node.name as ts.Expression, textOf(s, init), lineOf(s, node));
      walkNode(s, init, visit);
      return;
    }
    if (ts.isObjectLiteralExpression(node)) {
      s.objectStack.push("");
      for (const prop of node.properties) recordObjectMember(s, prop, lineOf(s, node));
      s.objectStack.pop();
      return;
    }
    if (ts.isClassLike(node)) {
      const clsName = (node as ts.ClassLikeDeclaration).name;
      if (clsName !== undefined) {
        const base = textOf(s, clsName);
        if (base.length > 0) walkClass(s, node as ts.ClassLikeDeclaration, base, lineOf(s, node));
      }
      return;
    }
    // Any other statement (ExpressionStatement, if/for/try/switch, ...):
    // recurse into its children with the same visitor.
    walkNode(s, node, visit);
  };
  walkNode(s, body as ts.Node, visit);
}

function nameOfFunction(s: State, node: ts.Node): string {
  if (
    ts.isFunctionDeclaration(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isGetAccessor(node) ||
    ts.isSetAccessor(node)
  ) {
    return node.name !== undefined ? textOf(s, node.name) : "";
  }
  if (ts.isConstructorDeclaration(node)) {
    const cls = s.classStack[s.classStack.length - 1];
    return cls !== undefined && cls.length > 0 ? `${cls}.#constructor` : "#constructor";
  }
  return "";
}

// NOTE: forEachChild has VISITOR semantics — a truthy callback return stops
// the iteration (visitNodes). The callback below returns nothing; a bare
// `(c) => children.push(c)` would return the new length and stop after the
// FIRST child (this silently dropped every statement after the first).
function walkNode(s: State, node: ts.Node, visit?: (n: ts.Node) => void): void {
  const children: ts.Node[] = [];
  node.forEachChild((c) => {
    children.push(c);
  });
  for (const child of children) {
    if (visit !== undefined) visit(child);
  }
}

/** Generic walk for recorded-only structures: dynamics + interop, no summaries. */
function walkGeneric(s: State, node: ts.Node): void {
  const children: ts.Node[] = [];
  // block body: never return the truthy push count (see walkNode)
  node.forEachChild((c) => {
    children.push(c);
  });
  for (const child of children) {
    if (ts.isCallExpression(child)) {
      dynamicForCall(s, child);
      const callee = unwrapOptional(child.expression);
      if (ts.isIdentifier(callee)) {
        const t = callee.text;
        if (t === "__exportStar") s.interop.add("exportStar");
        if (t === "__importDefault") s.interop.add("importDefault");
        if (t === "eval") recordDynamic(s, "eval", child);
      }
      if (child.kind === ts.SyntaxKind.CallExpression) {
        const expr0 = child.expression as ts.Expression;
        if (expr0.kind === ts.SyntaxKind.ImportKeyword) {
          const arg = child.arguments[0];
          // a literal `import("dep")` is a normal (dynamic) import; the
          // non-literal marker was already recorded by dynamicForCall
          if (arg !== undefined && isStringLiteral(arg)) {
            s.imports.push({
              module: arg.text,
              kind: "import-dynamic",
              bindings: [],
              dynamic: true,
              line: lineOf(s, child),
            });
          }
        }
      }
    }
    if (ts.isNewExpression(child)) {
      const callee = unwrapOptional(child.expression);
      if (ts.isIdentifier(callee) && callee.text === "Function") recordDynamic(s, "new-function", child);
    }
    if (ts.isCallExpression(child) || ts.isNewExpression(child)) {
      // recurse into call arguments for deeper dynamics
      walkGeneric(s, child);
    }
  }
}

// --- entry point -------------------------------------------------------------

/**
 * Parse a module text into the serializable IR (parse-only; no type-checking,
 * no program — determinism comes from the parser, plan 5.4).
 */
export function parseModule(file: string, text: string, options: ParseOptions = {}): ModuleIR {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.ESNext, true, scriptKindOf(file, options));
  const s: State = {
    sf,
    file,
    imports: [],
    exports: [],
    functions: [],
    topLevel: [],
    moduleAssignments: [],
    dynamic: [],
    interop: new Set<string>(),
    unresolvedImports: [],
    fnStack: [],
    objectStack: [],
    classStack: [],
    classBases: [],
  };

  for (const stmt of sf.statements) {
    walkTopLevel(s, stmt);
  }

  return {
    schemaVersion: Number(SCHEMA_VERSION),
    file,
    moduleFormat: formatOf(file, options),
    imports: s.imports,
    exports: s.exports,
    topLevel: s.topLevel,
    moduleAssignments: s.moduleAssignments,
    functions: s.functions,
    classBases: s.classBases,
    dynamic: s.dynamic,
    interop: [...s.interop].sort(),
    unresolvedImports: s.unresolvedImports,
  };
}
