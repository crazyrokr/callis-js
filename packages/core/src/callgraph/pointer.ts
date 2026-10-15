// M7a — inclusion-based pointer analysis (Andersen style, object-sensitive;
// ADR 0011 soundness contract, ADR 0016 engine/policy split).
//
// The pure solver core: a class lattice (extends chains, cycle-safe) and
// the dispatch closure of a receiver's type set. The builder feeds it the
// type facts collected per function (new / return / copy / argument flow);
// it answers "which classes may a receiver refer to, and which of their
// methods may therefore execute".
//
// Soundness (why the refinement never drops a real path):
//   - a type set is an OVER-approximation of the runtime receiver set
//     (union-based, no subtraction — the classic inclusion semantics);
//   - the dispatch closure includes every SUPERTYPE of every class in the
//     set: an instance of D executes D's methods and, for any inherited
//     method, the nearest unoverridden implementation on the chain —
//     including the whole chain over-approximates that;
//   - classes in the set always have a `new` (directly or through a
//     return/copy chain), so supertypes that were never instantiated are
//     still correct targets: their inherited methods run on the
//     instantiated subclass's instances;
//   - an UNKOWN receiver (empty set) falls back to the default RTA —
//     the refinement only ever replaces the default at sites where the
//     receiver's types are provable, and the default remains the union
//     of everything else.

/** Class node id → base class node id (null = no base / base unresolved). */
export type ExtendsMap = Map<string, string | null>;

/**
 * Supertype closure per class: the class itself plus every ancestor
 * (extends chain). Memoized with a cycle guard (A extends B, B extends A
 * terminates: each class sees the cycle, no infinite chain).
 */
export function supertypeClosures(extendsEdges: ExtendsMap): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  const visit = (id: string): Set<string> => {
    const done = out.get(id);
    if (done !== undefined) return done;
    const set = new Set<string>([id]);
    out.set(id, set); // provisional: the cycle guard
    const base = extendsEdges.get(id);
    if (base !== undefined && base !== null) {
      for (const u of visit(base)) set.add(u);
    }
    return set;
  };
  for (const id of extendsEdges.keys()) visit(id);
  return out;
}

/**
 * Dispatch closure of a receiver type set: every class that may execute
 * the receiver's method — each typed class plus its full supertype chain
 * (inherited dispatch). A subclass instance never executes a method of a
 * class outside its own chain, and a base-typed receiver never receives
 * an instance of a class that was not typed into it, so the closure is a
 * sound over-approximation of the runtime dispatch set.
 */
export function dispatchClosure(receiver: Iterable<string>, closures: Map<string, Set<string>>): Set<string> {
  const out = new Set<string>();
  for (const c of receiver) {
    for (const u of closures.get(c) ?? [c]) out.add(u);
  }
  return out;
}
