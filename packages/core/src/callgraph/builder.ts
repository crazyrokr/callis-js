// Demand-driven call-graph builder (plan section 5.5).
//
// Default mode: RTA-analogue, field-based, flow-insensitive.
//   1. Direct calls resolve through module export tables (cross-module,
//      re-exports and namespace imports included).
//   2. `new C()` instantiates; `x.m()` resolves methods named m on
//      instantiated classes (RTA pruning) filtered by receiver flow where
//      known.
//   3. Function values flow through assignments, arguments, returns and
//      exports (a lightweight 0-CFA).
//   4. Library models (packages/models) cover the standard callback shapes.
//   5. Unresolvable constructs become dynamic-risk markers — recorded,
//      never dropped (ADR 0011).
//
// `--cha`: `x.m()` targets every loaded function or method named m.
// `--over-approximate-dynamic`: computed calls with unknown keys fall back
// to every method of instantiated classes.
//
// Only modules reachable from the entry points are loaded, so a 30k-file
// node_modules costs what the application actually touches. A literal
// `import()` is treated as an eager import edge (over-approximation: more
// edges, never fewer).

import type { FunctionSummary, ModuleIR } from "../frontend/index.js";
import { type LibraryModel, callbackArgsOf, modelForCall } from "./models.js";
import {
  type BuildInput,
  type CallGraph,
  type EdgeKind,
  type GraphEdge,
  type GraphNode,
  type MarkerRecord,
  classId,
  functionId,
  moduleInitId,
} from "./types.js";
import { MODULE_INIT_NAME } from "./types.js";

interface FunctionState {
  summary: FunctionSummary;
  file: string;
  id: string;
  node: GraphNode;
  /** Local name → target functions (0-CFA flow set). */
  flow: Map<string, Set<string>>;
  /** Parameter name → functions passed at call sites. */
  paramFlow: Map<string, Set<string>>;
  /** Functions returned by this function. */
  returnFlow: Set<string>;
  /** "a.b" / "Foo.m" (prototype normalized) → assigned functions. */
  memberFlow: Map<string, Set<string>>;
}

interface ImportLink {
  specifier: string;
  kind: "esm" | "require" | "import-dynamic";
  line: number;
  /** local binding → exported name ("default" | name | "*" namespace | "<module>" require object). */
  bindings: { local: string; exported: string }[];
  target: string | null;
}

interface ModuleState {
  ir: ModuleIR;
  initNode: GraphNode;
  /** Module-scope functions by (first) name. */
  functions: Map<string, FunctionState>;
  classes: Map<string, GraphNode>;
  imports: ImportLink[];
}

export interface BuildResult {
  graph: CallGraph;
  /** Entry points that named a function no loaded module provides. */
  unresolvedEntries: string[];
}

export class CallGraphBuilder {
  private modules = new Map<string, ModuleState>();
  private functions = new Map<string, FunctionState>();
  private classNodes = new Map<string, GraphNode>();
  private edges: GraphEdge[] = [];
  private markers: MarkerRecord[] = [];
  private worklist: string[] = [];
  private activated = new Set<string>();
  /** Instantiated class node ids (RTA). */
  private instantiated = new Set<string>();
  /** Receiver text → instantiated class node ids (from `x = new C()`). */
  private newFlow = new Map<string, Set<string>>();
  /** Emitter registrations: receiver text → event name → handler ids. */
  private emitterReg = new Map<string, Map<string, Set<string>>>();
  /** Class node id → member function ids. */
  private classMembers = new Map<string, string[]>();
  /** file → className → base class name (from IR classBases). */
  private classHierarchy = new Map<string, Map<string, string>>();
  /** Nodes currently being processed (cycle guard for eager processing). */
  private processing = new Set<string>();
  /** Nodes fully processed (idempotency across worklist + eager paths). */
  private processed = new Set<string>();

  constructor(private readonly input: BuildInput) {}

  async build(): Promise<BuildResult> {
    const unresolved: string[] = [];
    for (const ep of this.input.entryPoints) {
      const mod = await this.loadModule(ep.file);
      if (mod === null) {
        unresolved.push(`${ep.file}#<unreadable>`);
        continue;
      }
      // Module evaluation runs on load: an entry file's import-time side
      // effects are part of the program even when the entry is a function
      // (never drop import-time effects).
      this.activate(mod.initNode.id);
      if (ep.name !== MODULE_INIT_NAME) {
        const fn = mod.functions.get(ep.name);
        if (fn !== undefined) this.activate(fn.id);
        else unresolved.push(`${ep.file}#${ep.name}`);
      }
    }
    await this.run();
    return { graph: this.emit(), unresolvedEntries: unresolved };
  }

  private async run(): Promise<void> {
    while (this.worklist.length > 0) {
      const id = this.worklist.shift() as string;
      await this.processNode(id);
    }
  }

  /**
   * Process one node now, not at worklist-drain time. Callers process the
   * target eagerly so that `const fn = make(); fn()` sees make's return flow
   * in the very next statement (order-dependent flow would be lost on a FIFO
   * drain). In-progress nodes are skipped (cycles): each function's own pass
   * resolves its own call sites, and the analysis is monotone.
   */
  private async processNode(id: string): Promise<void> {
    if (this.processing.has(id) || this.processed.has(id)) return;
    this.processing.add(id);
    try {
      if (id.endsWith(`#${MODULE_INIT_NAME}`)) {
        const file = id.slice(0, -(MODULE_INIT_NAME.length + 1));
        const mod = this.modules.get(file);
        if (mod !== undefined) await this.processInit(mod);
      } else {
        const fn = this.functions.get(id);
        if (fn !== undefined) await this.processFunction(fn);
      }
    } finally {
      this.processing.delete(id);
      this.processed.add(id);
    }
  }

  // --- module loading -------------------------------------------------------

  private async loadModule(file: string): Promise<ModuleState | null> {
    const existing = this.modules.get(file);
    if (existing !== undefined) return existing;
    const ir = await this.input.ir(file);
    if (ir === null) return null;

    const mod: ModuleState = {
      ir,
      initNode: { id: moduleInitId(file), kind: "module-init", file, name: MODULE_INIT_NAME, line: 1 },
      functions: new Map(),
      classes: new Map(),
      imports: [],
    };
    this.modules.set(file, mod);

    for (const summary of ir.functions) {
      const id = functionId(file, summary.name);
      const state: FunctionState = {
        summary,
        file,
        id,
        node: { id, kind: "function", file, name: summary.name, line: summary.line },
        flow: new Map(),
        paramFlow: new Map(),
        returnFlow: new Set(),
        memberFlow: new Map(),
      };
      this.functions.set(state.id, state);
      if (!mod.functions.has(summary.name)) mod.functions.set(summary.name, state);
    }

    // Class nodes: declared classes plus qualified member summaries (Name.x).
    const declared = new Set(ir.classBases.map((c) => c.name));
    const members = new Map<string, Set<string>>();
    for (const summary of ir.functions) {
      const dot = summary.name.lastIndexOf(".");
      if (dot > 0) {
        const cls = summary.name.slice(0, dot);
        if (!declared.has(cls) && !ir.classBases.some((c) => c.name === cls)) continue;
        const set = members.get(cls) ?? new Set<string>();
        set.add(summary.name);
        members.set(cls, set);
      }
    }
    for (const name of [...new Set([...declared, ...members.keys()])].sort()) {
      const line = ir.classBases.find((c) => c.name === name)?.line ?? 1;
      const node: GraphNode = { id: classId(file, name), kind: "class", file, name, line };
      this.classNodes.set(node.id, node);
      mod.classes.set(name, node);
      // Member function NODE IDS (`file#Name.member`), not bare names — edges
      // and the worklist address nodes by their full id.
      this.classMembers.set(
        node.id,
        [...(members.get(name) ?? [])].sort().map((n) => functionId(file, n)),
      );
    }
    const hierarchy = new Map<string, string>();
    for (const c of ir.classBases) {
      if (c.base !== undefined) hierarchy.set(c.name, c.base);
    }
    this.classHierarchy.set(file, hierarchy);

    mod.imports = this.importLinks(ir);
    for (const imp of mod.imports) imp.target = this.resolveTarget(file, imp.specifier, imp.kind);

    // Dynamic-risk markers of a loaded module are part of the graph (ADR 0011).
    this.recordMarkers(mod);
    return mod;
  }

  private importLinks(ir: ModuleIR): ImportLink[] {
    // Merge IR import records per specifier+kind (a re-export link and a real
    // import of the same specifier share one graph edge).
    const bySpec = new Map<
      string,
      { specifier: string; kind: ImportLink["kind"]; line: number; bindings: { local: string; exported: string }[] }
    >();
    for (const imp of ir.imports) {
      // Non-literal specifiers are markers, not edges. A literal `import()`
      // (import-dynamic) IS an eager import edge: over-approximation, more
      // edges never fewer (documented in the module header).
      if (imp.dynamic && imp.kind !== "import-dynamic") continue;
      if (imp.kind !== "esm" && imp.kind !== "require" && imp.kind !== "import-dynamic") continue;
      const key = `${imp.kind}\u0000${imp.module}`;
      const cur = bySpec.get(key) ?? {
        specifier: imp.module,
        kind: imp.kind,
        line: imp.line,
        bindings: [] as { local: string; exported: string }[],
      };
      cur.bindings.push(
        ...imp.bindings.map((b) => ({
          local: b.local,
          exported: imp.kind === "require" ? "<module>" : imp.kind === "import-dynamic" ? "*" : b.exported,
        })),
      );
      bySpec.set(key, cur);
    }
    return [...bySpec.values()].map((cur) => ({
      specifier: cur.specifier,
      kind: cur.kind,
      line: cur.line,
      bindings: cur.bindings,
      target: null,
    }));
  }

  private resolveTarget(fromFile: string, spec: string, kind: ImportLink["kind"]): string | null {
    const format = kind === "require" ? "require" : "import";
    return this.input.linker.resolve(fromFile, spec, format);
  }

  private activate(id: string): void {
    if (this.activated.has(id)) return;
    this.activated.add(id);
    this.worklist.push(id);
  }

  private addEdge(from: string, to: string, kind: EdgeKind, line: number, via?: string): void {
    this.edges.push({ from, to, kind, line, ...(via !== undefined ? { via } : {}) });
  }

  // --- module-init processing -----------------------------------------------

  private async processInit(mod: ModuleState): Promise<void> {
    const init = mod.initNode.id;
    for (const imp of mod.imports) {
      if (imp.target === null) continue;
      const targetMod = await this.loadModule(imp.target);
      if (targetMod === null) continue;
      this.addEdge(init, targetMod.initNode.id, "import", imp.line);
      this.activate(targetMod.initNode.id);
    }
    for (const stmt of mod.ir.topLevel) {
      if (stmt.kind !== "call") continue;
      let fn: FunctionState | undefined;
      if (stmt.functionName !== undefined) {
        fn = mod.functions.get(stmt.functionName);
      } else {
        // Hoisting: `configure();` before `function configure() {}` — the IR
        // entry carries no functionName (the declaration came later in source
        // order). Resolve the plain identifier call by its shape prefix
        // (`name(` — member calls like `o.m(` never match).
        const m = /^([A-Za-z_$][\w$]*)\(/.exec(stmt.shape);
        if (m !== null && m[1] !== undefined) fn = mod.functions.get(m[1]);
      }
      if (fn !== undefined) {
        this.addEdge(init, fn.id, "call", stmt.line);
        this.activate(fn.id);
        continue;
      }
      if (stmt.shape.startsWith("(") || stmt.shape.startsWith("await (")) {
        // IIFE: match the top-level function recorded at this line
        const iife = this.topFunctionAt(mod, stmt.line);
        if (iife !== null) {
          this.addEdge(init, iife.id, "call", stmt.line);
          this.activate(iife.id);
        }
      }
    }
  }

  private topFunctionAt(mod: ModuleState, line: number): FunctionState | null {
    const candidates = [...mod.functions.values()].filter((f) => f.summary.top && f.summary.line === line);
    return candidates.length === 1 ? (candidates[0] ?? null) : null;
  }

  // --- function processing ---------------------------------------------------

  private async processFunction(fn: FunctionState): Promise<void> {
    this.seedFlow(fn);
    for (const a of fn.summary.assignments) await this.recordAssignment(fn, a);
    for (const r of fn.summary.returns) {
      for (const t of await this.refTargets(fn, r, true)) fn.returnFlow.add(t);
    }
    for (const c of fn.summary.calls) await this.resolveCallSite(fn, c);
  }

  private seedFlow(fn: FunctionState): void {
    // Flow-insensitive scoping: every function in the same module is in scope.
    for (const local of this.functions.values()) {
      if (local.file !== fn.file || local.id === fn.id) continue;
      const set = fn.flow.get(local.summary.name) ?? new Set<string>();
      set.add(local.id);
      fn.flow.set(local.summary.name, set);
    }
    for (const [param, targets] of fn.paramFlow) {
      const set = fn.flow.get(param) ?? new Set<string>();
      for (const t of targets) set.add(t);
      fn.flow.set(param, set);
    }
  }

  /**
   * Flow of a value expression (identifier / member / call result).
   * `eager` processes not-yet-processed callees so return flow is complete
   * at resolution time; assignment recording uses eager=false (best effort,
   * no early processing — a callee processed before the caller's call sites
   * ran would miss parameter flow).
   */
  private async refTargets(fn: FunctionState, text: string, eager: boolean = false): Promise<Set<string>> {
    const out = new Set<string>();
    if (isIdentifierText(text)) {
      for (const t of await this.flowOf(fn, text, eager)) out.add(t);
      // A local name may carry an IMPORTED binding (`const alias = handler;`)
      // — the flow map does not seed import bindings, so resolve them here.
      const via = await this.importTarget(fn.file, text, text, false);
      if (via !== null) out.add(via);
      return out;
    }
    if (isMemberText(text)) {
      for (const t of fn.memberFlow.get(text) ?? []) out.add(t);
      return out;
    }
    if (isCallText(text)) {
      // `x(...)` used as a value: the call's return flow
      const callee = text.slice(0, text.indexOf("("));
      if (isIdentifierText(callee)) {
        for (const t of await this.flowOf(fn, callee, eager)) {
          for (const r of await this.returnFlowOf(t, eager)) out.add(r);
        }
      }
      return out;
    }
    return out;
  }

  /**
   * Functions a local name may carry: direct flow plus RETURN flow of
   * assigned calls — `const fn = make(); fn()` reaches make's returns.
   * With `eager` the callee is processed on the spot (call resolution);
   * without, only already-computed return flow is used (assignment time).
   */
  private async flowOf(fn: FunctionState, name: string, eager: boolean = false): Promise<Set<string>> {
    const out = new Set<string>(fn.flow.get(name) ?? []);
    for (const a of fn.summary.assignments) {
      if (a.kind !== "identifier" || a.target !== name || !isCallText(a.value)) continue;
      const callee = a.value.slice(0, a.value.indexOf("("));
      if (!isIdentifierText(callee)) continue;
      for (const t of fn.flow.get(callee) ?? []) {
        for (const r of await this.returnFlowOf(t, eager)) out.add(r);
      }
      const via = await this.importTarget(fn.file, callee, callee, false);
      if (via !== null) for (const r of await this.returnFlowOf(via, eager)) out.add(r);
    }
    return out;
  }

  private async returnFlowOf(id: string, eager: boolean): Promise<Set<string>> {
    const f = this.functions.get(id);
    if (f === undefined) return new Set<string>();
    if (eager) await this.processNode(id);
    return f.returnFlow;
  }

  private async recordAssignment(fn: FunctionState, a: FunctionSummary["assignments"][number]): Promise<void> {
    const valueTargets = await this.refTargets(fn, a.value);
    const member = a.kind === "member" || a.kind === "prototype" || a.kind === "class-field";
    if (a.kind === "identifier") {
      const set = fn.flow.get(a.target) ?? new Set<string>();
      for (const t of valueTargets) set.add(t);
      fn.flow.set(a.target, set);
    } else if (member) {
      const key = a.kind === "prototype" ? a.target.replace(/\.prototype\./, ".") : a.target;
      const set = fn.memberFlow.get(key) ?? new Set<string>();
      for (const t of valueTargets) set.add(t);
      fn.memberFlow.set(key, set);
    }
    // `x = new C()`: receiver flow to instantiated classes (RTA, plan 5.5 item 2)
    const m = /^new\s+([A-Za-z_$][\w$]*)/.exec(a.value);
    if (m !== null && m[1] !== undefined) {
      const cls = this.classByName(fn.file, m[1]) ?? (await this.classViaImport(fn.file, m[1]));
      if (cls !== null) {
        const nf = this.newFlow.get(a.target) ?? new Set<string>();
        nf.add(cls.id);
        this.newFlow.set(a.target, nf);
      }
    }
    // bind alias (model kind "alias"): `f = g.bind(ctx)` flows to g
    const bind = /^([A-Za-z_$][\w$]*)\.bind\(/.exec(a.value);
    if (bind !== null && bind[1] !== undefined && a.kind === "identifier") {
      const base = await this.refTargets(fn, bind[1]);
      const set2 = fn.flow.get(a.target) ?? new Set<string>();
      for (const t of base) set2.add(t);
      fn.flow.set(a.target, set2);
    }
  }

  private async resolveCallSite(fn: FunctionState, c: FunctionSummary["calls"][number]): Promise<void> {
    switch (c.shape) {
      case "new":
        await this.resolveNew(fn, c);
        return;
      case "super":
        this.resolveSuper(fn, c);
        return;
      case "member":
      case "optional":
        await this.resolveMember(fn, c);
        return;
      case "computed":
        await this.resolveComputed(fn, c);
        return;
      case "direct":
      case "tagged":
        await this.resolveDirect(fn, c);
        return;
      default:
        // "dynamic" shape (uncategorizable callee): no edge; the IR marker
        // (if any) carries the risk.
        return;
    }
  }

  /** Argument flow into a resolved target: `f(g)` flows g into f's param. */
  private async recordArgFlow(fn: FunctionState, targetId: string, args: string[]): Promise<void> {
    const target = this.functions.get(targetId);
    if (target === undefined) return;
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg === undefined) continue;
      const param = target.summary.params[i];
      if (param === undefined || !isIdentifierText(arg)) continue;
      const set = target.paramFlow.get(param) ?? new Set<string>();
      for (const t of await this.refTargets(fn, arg, true)) set.add(t);
      target.paramFlow.set(param, set);
    }
  }

  private async callTargets(
    fn: FunctionState,
    targets: Set<string>,
    c: FunctionSummary["calls"][number],
  ): Promise<void> {
    for (const t of [...targets].sort()) {
      this.addEdge(fn.id, t, "call", c.line);
      await this.recordArgFlow(fn, t, c.args);
      this.activate(t);
      await this.processNode(t);
    }
  }

  private async resolveDirect(fn: FunctionState, c: FunctionSummary["calls"][number]): Promise<void> {
    const name = c.callee;
    const targets = new Set<string>(await this.flowOf(fn, name, true));
    const viaImport = await this.importTarget(fn.file, name, name, false);
    if (viaImport !== null) targets.add(viaImport);
    if (targets.size > 0) {
      await this.callTargets(fn, targets, c);
      return;
    }
    const model = modelForCall(name, false, this.input.models);
    if (model !== null) {
      await this.modelCall(fn, c, model);
      return;
    }
    // A global without a model (console.log, ...): no edge, no marker —
    // ordinary library calls outside the catalogue are not dynamic risk.
  }

  private async resolveMember(fn: FunctionState, c: FunctionSummary["calls"][number]): Promise<void> {
    const dot = c.callee.lastIndexOf(".");
    if (dot <= 0) {
      await this.resolveDirect(fn, c);
      return;
    }
    const base = c.callee.slice(0, dot);
    const m = c.callee.slice(dot + 1);
    const targets = new Set<string>();

    // 1. RTA: methods named m on instantiated classes whose instance flows
    //    to the receiver — declared members AND `Cls.prototype.m = fn` flow.
    for (const [clsId, members] of this.classMembers) {
      if (!this.instantiated.has(clsId)) continue;
      const receivers = this.newFlow.get(base);
      if (receivers === undefined || !receivers.has(clsId)) continue;
      for (const member of members) {
        if (member.endsWith(`.${m}`) && !member.endsWith(".#constructor")) targets.add(member);
      }
      const protoKey = `${this.classNodes.get(clsId)?.name ?? ""}.${m}`;
      for (const t of fn.memberFlow.get(protoKey) ?? []) targets.add(t);
    }
    // 2. member flow (a.b = fn / Foo.prototype.m = fn)
    for (const t of fn.memberFlow.get(c.callee) ?? []) targets.add(t);
    // 3. import bindings: require module objects, namespaces, default/named
    const viaImport = await this.importTarget(fn.file, base, m, true);
    if (viaImport !== null) targets.add(viaImport);
    // 4. library models (map/forEach/then/on/emit/...) — receiver-agnostic
    const model = modelForCall(m, true, this.input.models);
    if (model !== null) await this.modelCall(fn, c, model, base);
    // 5. --cha: every loaded function or method named m (plan 5.5)
    if (this.input.options?.cha === true) {
      for (const f of [...this.functions.values()].sort((a, b) => a.id.localeCompare(b.id))) {
        if (f.summary.name === m || f.summary.name.endsWith(`.${m}`)) {
          this.addEdge(fn.id, f.id, "call", c.line, "cha");
          this.activate(f.id);
        }
      }
    }
    await this.callTargets(fn, targets, c);
  }

  private async resolveComputed(fn: FunctionState, c: FunctionSummary["calls"][number]): Promise<void> {
    const m = /^([A-Za-z_$][\w$.]*)\[\s*(['"])(.+)\2\s*\]$/.exec(c.callee);
    if (m !== null && m[1] !== undefined && m[3] !== undefined) {
      const proxy: FunctionSummary["calls"][number] = { ...c, shape: "member", callee: `${m[1]}.${m[3]}` };
      await this.resolveMember(fn, proxy);
      return;
    }
    // Non-literal key: name-based fallback only under --over-approximate-dynamic
    if (this.input.options?.overApproximateDynamic === true) {
      const base = c.callee.split("[")[0] ?? "";
      const targets = new Set<string>();
      for (const [clsId, members] of this.classMembers) {
        if (!this.instantiated.has(clsId)) continue;
        const receivers = this.newFlow.get(base);
        if (receivers === undefined || !receivers.has(clsId)) continue;
        for (const member of members) {
          if (!member.endsWith(".#constructor")) targets.add(member);
        }
      }
      for (const t of [...targets].sort()) {
        this.addEdge(fn.id, t, "call", c.line, "over-approx");
        this.activate(t);
      }
    }
    // else: no edge; the computed-call marker (IR) carries the risk.
  }

  private async resolveNew(fn: FunctionState, c: FunctionSummary["calls"][number]): Promise<void> {
    const name = c.callee;
    const cls = this.classByName(fn.file, name) ?? (await this.classViaImport(fn.file, name));
    if (cls !== null) {
      this.instantiated.add(cls.id);
      this.addEdge(fn.id, cls.id, "instantiation", c.line);
      const ctor = this.classMembers.get(cls.id)?.find((x) => x.endsWith(".#constructor"));
      if (ctor !== undefined) {
        this.addEdge(fn.id, ctor, "call", c.line);
        this.activate(ctor);
      }
      return;
    }
    // `new f()` where f is a function (or unknown): call the flow set
    await this.callTargets(fn, fn.flow.get(name) ?? new Set<string>(), c);
  }

  private async classViaImport(file: string, name: string): Promise<GraphNode | null> {
    const mod = this.modules.get(file);
    if (mod === undefined) return null;
    for (const imp of mod.imports) {
      if (imp.target === null) continue;
      const b = imp.bindings.find((x) => x.local === name);
      if (b === undefined) continue;
      const targetMod = await this.loadModule(imp.target);
      if (targetMod === null) continue;
      this.activate(targetMod.initNode.id);
      const cls =
        targetMod.classes.get(name) ??
        targetMod.classes.get(b.exported === "*" || b.exported === "<module>" ? name : b.exported) ??
        this.classExportedAs(targetMod, name);
      if (cls !== undefined) return cls;
    }
    return null;
  }

  /** A class reachable through an export entry of `mod` under local name. */
  private classExportedAs(mod: ModuleState, localName: string): GraphNode | undefined {
    const byName = mod.classes.get(localName);
    if (byName !== undefined) return byName;
    const def = mod.ir.exports.find((e) => e.kind === "default");
    if (def !== undefined && def.local !== undefined) {
      const cls = mod.classes.get(def.local);
      if (cls !== undefined) return cls;
    }
    const named = mod.ir.exports.find((e) => e.kind === "named" && e.name === localName);
    if (named !== undefined && named.local !== undefined) {
      const cls = mod.classes.get(named.local) ?? mod.classes.get(named.name);
      if (cls !== undefined) return cls;
    }
    return undefined;
  }

  private classByName(file: string, name: string): GraphNode | null {
    return this.modules.get(file)?.classes.get(name) ?? null;
  }

  private resolveSuper(fn: FunctionState, c: FunctionSummary["calls"][number]): void {
    const dot = fn.summary.name.lastIndexOf(".");
    if (dot <= 0) return; // super outside a class: nothing to link
    const clsName = fn.summary.name.slice(0, dot);
    const baseName = this.classHierarchy.get(fn.file)?.get(clsName);
    if (baseName === undefined) return;
    const base = this.classByName(fn.file, baseName) ?? this.classByNameOfAnyLoaded(baseName);
    if (base === null) return;
    const ctor = this.classMembers.get(base.id)?.find((x) => x.endsWith(".#constructor"));
    if (ctor !== undefined) {
      this.addEdge(fn.id, ctor, "super", c.line);
      this.activate(ctor);
    }
  }

  private classByNameOfAnyLoaded(name: string): GraphNode | null {
    for (const node of this.classNodes.values()) {
      if (node.name === name) return node;
    }
    return null;
  }

  /** Library-model calls: edges to the callback arguments. */
  private async modelCall(
    fn: FunctionState,
    c: FunctionSummary["calls"][number],
    model: LibraryModel,
    receiver?: string,
  ): Promise<void> {
    const positions = callbackArgsOf(model);
    for (const pos of positions) {
      const arg = c.args[pos];
      if (arg === undefined) continue;
      if (model.kind === "emitter" && model.eventArg !== undefined && receiver !== undefined) {
        const event = c.args[model.eventArg];
        if (event !== undefined && isQuoted(event)) {
          const byReceiver = this.emitterReg.get(receiver) ?? new Map<string, Set<string>>();
          const handlers = byReceiver.get(unquote(event)) ?? new Set<string>();
          for (const t of await this.refTargets(fn, arg, true)) handlers.add(t);
          byReceiver.set(unquote(event), handlers);
          this.emitterReg.set(receiver, byReceiver);
          for (const t of [...handlers].sort()) {
            this.addEdge(fn.id, t, "call", c.line, `model:${model.name}`);
            this.activate(t);
          }
        }
        continue;
      }
      if (model.kind === "emitter-emit" && model.eventArg !== undefined && receiver !== undefined) {
        const event = c.args[model.eventArg];
        if (event !== undefined && isQuoted(event)) {
          const handlers = this.emitterReg.get(receiver)?.get(unquote(event));
          if (handlers !== undefined) {
            for (const t of [...handlers].sort()) {
              this.addEdge(fn.id, t, "call", c.line, "model:emit");
              this.activate(t);
            }
          }
        }
        continue;
      }
      for (const t of [...(await this.refTargets(fn, arg, true))].sort()) {
        this.addEdge(fn.id, t, "call", c.line, `model:${model.name}`);
        this.activate(t);
      }
    }
  }

  // --- import binding resolution ---------------------------------------------

  /**
   * Resolve `local` (a binding in `file`) to a function in the imported
   * module. `isMember` distinguishes `dep()` / `ns.m()` / `dep.m()` — module
   * objects (require, namespaces, default) resolve members through the
   * export table; named values resolve only direct calls.
   */
  private async importTarget(
    file: string,
    local: string,
    memberName: string,
    isMember: boolean,
  ): Promise<string | null> {
    const mod = this.modules.get(file);
    if (mod === undefined) return null;
    for (const imp of mod.imports) {
      if (imp.target === null) continue;
      const b = imp.bindings.find((x) => x.local === local);
      if (b === undefined) continue;
      const targetMod = await this.loadModule(imp.target);
      if (targetMod === null) continue;
      // Importing a module runs its import-time code: every loaded module's
      // module-init node is processed (idempotent via the activated set).
      this.activate(targetMod.initNode.id);

      if (imp.kind === "require") {
        // the module object: direct call → default export, member → export
        const wanted = isMember ? memberName : "default";
        const f = await this.exportFunction(targetMod, wanted);
        if (f !== undefined) return f.id;
        continue;
      }
      if (b.exported === "*") {
        if (!isMember) continue; // a namespace is not callable
        const f = await this.exportFunction(targetMod, memberName);
        if (f !== undefined) return f.id;
        continue;
      }
      if (b.exported === "default") {
        if (isMember) continue; // member access on the default VALUE, not the module
        const f = await this.exportFunction(targetMod, "default");
        if (f !== undefined) return f.id;
        continue;
      }
      // a named value: only direct calls resolve through the export table
      if (isMember) continue;
      const f = await this.exportFunction(targetMod, b.exported);
      if (f !== undefined) return f.id;
    }
    return null;
  }

  /**
   * The function `mod` exports under `exportName`. Direct exports resolve
   * through the export table; re-exports (`export { x } from "b"`, `export *
   * from "b"`) follow the import link into the source module (cycle-safe:
   * each module is searched at most once per chain).
   */
  private async exportFunction(
    mod: ModuleState,
    exportName: string,
    seen: Set<string> = new Set<string>(),
  ): Promise<FunctionState | undefined> {
    if (seen.has(mod.ir.file)) return undefined;
    seen.add(mod.ir.file);
    if (exportName === "default") {
      const def = mod.ir.exports.find((e) => e.kind === "default");
      if (def !== undefined && def.local !== undefined) {
        const f = mod.functions.get(def.local);
        if (f !== undefined) return f;
      }
      const named = mod.functions.get("default");
      if (named !== undefined) return named;
    } else {
      const entries = mod.ir.exports.filter((e) => e.name === exportName && e.kind !== "star" && e.kind !== "default");
      for (const e of entries) {
        if (e.local !== undefined) {
          const f = mod.functions.get(e.local);
          if (f !== undefined) return f;
        }
        const f = mod.functions.get(e.name);
        if (f !== undefined) return f;
      }
    }
    // Re-export: `export { x } from "b"` (named) and `export * from "b"`
    // (star — any name). The source module loads at import time (M3 records
    // the link), so resolution follows it.
    const reExports = mod.ir.exports
      .filter((e) => e.from !== undefined)
      .sort((a, b) => ((a.from ?? "") + a.name).localeCompare((b.from ?? "") + b.name));
    for (const e of reExports) {
      if (e.kind !== "star" && e.name !== exportName) continue;
      const link = mod.imports.find((i) => i.specifier === e.from && i.target !== null);
      if (link === undefined || link.target === null) continue;
      const targetMod = await this.loadModule(link.target);
      if (targetMod === null) continue;
      this.activate(targetMod.initNode.id);
      // `export { x as y } from "b"` resolves x in b; `export *` keeps the
      // requested name; a same-name re-export has local === name.
      const sourceName = e.kind === "named" ? (e.local ?? exportName) : exportName;
      const f = await this.exportFunction(targetMod, sourceName, seen);
      if (f !== undefined) return f;
    }
    return undefined;
  }

  // --- markers -----------------------------------------------------------------

  private recordMarkers(mod: ModuleState): void {
    for (const d of mod.ir.dynamic) {
      let scopedTo: string | null = null;
      if (d.functionName !== undefined) {
        const fn = mod.functions.get(d.functionName);
        scopedTo = fn?.id ?? null;
      } else {
        // module scope: the marker belongs to the module-init node
        scopedTo = mod.initNode.id;
      }
      this.markers.push({ kind: d.kind, line: d.line, shape: d.shape, scopedTo });
    }
  }

  // --- emission -----------------------------------------------------------------

  private emit(): CallGraph {
    const nodes: GraphNode[] = [];
    const seen = new Set<string>();
    const push = (n: GraphNode): void => {
      if (seen.has(n.id)) return;
      seen.add(n.id);
      nodes.push(n);
    };
    for (const mod of this.modules.values()) {
      push(mod.initNode);
      for (const fn of mod.functions.values()) push(fn.node);
      for (const cls of mod.classes.values()) push(cls);
    }
    nodes.sort((a, b) => a.id.localeCompare(b.id));

    const deduped = new Map<string, GraphEdge>();
    for (const e of this.edges) {
      const key = `${e.from}\u0000${e.to}\u0000${e.kind}\u0000${e.via ?? ""}\u0000${e.line}`;
      if (!deduped.has(key)) deduped.set(key, e);
    }
    const edges = [...deduped.values()].sort((a, b) =>
      a.from === b.from ? (a.to === b.to ? a.line - b.line : a.to.localeCompare(b.to)) : a.from.localeCompare(b.from),
    );

    const markers = [...this.markers].sort(
      (a, b) => (a.scopedTo ?? "").localeCompare(b.scopedTo ?? "") || a.line - b.line,
    );
    const unscoped = markers.filter((m) => m.scopedTo === null).length;
    return {
      nodes,
      edges,
      markers,
      entryPoints: [...this.input.entryPoints],
      stats: {
        modules: this.modules.size,
        nodes: nodes.length,
        edges: edges.length,
        dynamicMarkers: markers.length,
        unscopedMarkers: unscoped,
      },
    };
  }
}

/** Build the demand-driven graph for the given input. */
export async function buildGraph(input: BuildInput): Promise<BuildResult> {
  return new CallGraphBuilder(input).build();
}

// --- text-shape helpers ----------------------------------------------------------

function isIdentifierText(t: string): boolean {
  return /^[A-Za-z_$][\w$]*$/.test(t);
}

function isMemberText(t: string): boolean {
  return /^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)+$/.test(t);
}

function isCallText(t: string): boolean {
  return t.endsWith(")") && t.includes("(");
}

function isQuoted(t: string): boolean {
  return /^(['"]).*\1$/.test(t);
}

function unquote(t: string): string {
  return t.slice(1, -1);
}
