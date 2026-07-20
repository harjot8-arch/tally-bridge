/**
 * A ~120-line DOM, so the dashboard can be tested without Electron.
 *
 * NOT a test file (the runner globs `test/*.test.ts`) — a fixture the dashboard tests import.
 *
 * WHY NOT JSDOM: it is not in this repo's node_modules, and installing it is not on the table
 * while other agents are running against a shared tree. That turns out to be fine, and slightly
 * better than fine. The renderer only ever touches `createElement`, `createElementNS`,
 * `textContent`, `appendChild`, `setAttribute`, `classList` and `style.setProperty` — that is
 * the whole surface, deliberately, because the XSS rule bans the interesting half of the DOM.
 * A fixture this small is also a SECOND enforcement of that rule: there is no `innerHTML` here
 * to reach for, so renderer code that grew one would fail these tests before it ever reached
 * `hardening.test.ts`.
 *
 * What it therefore cannot tell you: anything about layout, CSS, or what a human sees. Those
 * need a real Electron window and a pair of eyes.
 */

export class FakeNode {
  readonly tagName: string;
  readonly namespaceURI: string | null;
  parentNode: FakeNode | null = null;
  readonly childNodes: FakeNode[] = [];
  readonly attributes = new Map<string, string>();
  readonly listeners = new Map<string, Array<() => void>>();
  readonly styles = new Map<string, string>();
  disabled = false;
  type = '';

  /** Set when `textContent` was assigned; children are cleared at the same moment, as in the DOM. */
  private ownText: string | null = null;

  constructor(tagName: string, namespaceURI: string | null = null) {
    this.tagName = tagName;
    this.namespaceURI = namespaceURI;
  }

  get firstChild(): FakeNode | null {
    return this.childNodes[0] ?? null;
  }

  appendChild(child: FakeNode): FakeNode {
    this.ownText = null;
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }

  removeChild(child: FakeNode): FakeNode {
    const i = this.childNodes.indexOf(child);
    if (i >= 0) this.childNodes.splice(i, 1);
    child.parentNode = null;
    return child;
  }

  set textContent(value: string) {
    this.childNodes.length = 0;
    this.ownText = value;
  }

  get textContent(): string {
    if (this.ownText !== null) return this.ownText;
    return this.childNodes.map((c) => c.textContent).join('');
  }

  set className(value: string) {
    this.attributes.set('class', value);
  }

  get className(): string {
    return this.attributes.get('class') ?? '';
  }

  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }

  getAttribute(name: string): string | null {
    return this.attributes.get(name) ?? null;
  }

  addEventListener(type: string, fn: () => void): void {
    const list = this.listeners.get(type) ?? [];
    list.push(fn);
    this.listeners.set(type, list);
  }

  /** Test-only: fire a listener, the way a click would. */
  click(): void {
    for (const fn of this.listeners.get('click') ?? []) fn();
  }

  readonly style = {
    setProperty: (k: string, v: string): void => {
      this.styles.set(k, v);
    },
  };

  readonly classList = {
    add: (c: string): void => this.setClasses([...this.classes(), c]),
    remove: (c: string): void => this.setClasses(this.classes().filter((x) => x !== c)),
    contains: (c: string): boolean => this.classes().includes(c),
    toggle: (c: string, force?: boolean): boolean => {
      const on = force ?? !this.classes().includes(c);
      if (on) this.classList.add(c);
      else this.classList.remove(c);
      return on;
    },
  };

  private classes(): string[] {
    return this.className.split(/\s+/).filter(Boolean);
  }

  private setClasses(list: string[]): void {
    this.className = [...new Set(list)].join(' ');
  }
}

export interface FakeDom {
  root: FakeNode;
  uninstall(): void;
}

/**
 * Install a document on the global. Call `uninstall()` in a `t.after` so tests do not leak into
 * each other.
 */
export function installDom(): FakeDom {
  const documentElement = new FakeNode('html');
  const document = {
    documentElement,
    createElement: (tag: string) => new FakeNode(tag),
    createElementNS: (ns: string, tag: string) => new FakeNode(tag, ns),
  };
  const g = globalThis as Record<string, unknown>;
  const hadDocument = 'document' in g;
  const previous = g.document;
  g.document = document;
  return {
    root: new FakeNode('div'),
    uninstall() {
      if (hadDocument) g.document = previous;
      else delete g.document;
    },
  };
}

// ---------------------------------------------------------------- queries

export function walk(node: FakeNode): FakeNode[] {
  return [node, ...node.childNodes.flatMap(walk)];
}

export function byClass(node: FakeNode, className: string): FakeNode[] {
  return walk(node).filter((n) => n.className.split(/\s+/).includes(className));
}

export function firstByClass(node: FakeNode, className: string): FakeNode | undefined {
  return byClass(node, className)[0];
}

export function byTag(node: FakeNode, tagName: string): FakeNode[] {
  return walk(node).filter((n) => n.tagName === tagName);
}

/** Every string a human would see, in document order. */
export function texts(node: FakeNode): string[] {
  return walk(node)
    .filter((n) => n.childNodes.length === 0)
    .map((n) => n.textContent)
    .filter((s) => s.length > 0);
}

/** The whole subtree as one string — for asserting that a hostile name is NOT markup. */
export function allText(node: FakeNode): string {
  return node.textContent;
}
