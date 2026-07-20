/**
 * Tiny DOM helpers.
 *
 * WHY NOT REACT — a deliberate deviation from the original plan.
 *
 * The plan called for a shared React component package consumed by both the desktop renderer
 * and the web dashboard. That was replaced by `packages/viewmodel` (pure logic, no DOM) plus a
 * thin renderer per surface, for three reasons:
 *
 *   1. The mobile decision is open. React components do NOT port to a native Swift/Kotlin
 *      client; pure view models do. Putting the shared layer at the logic boundary rather than
 *      the component boundary is what keeps all three options alive.
 *   2. These are cards. The rendering is a few hundred lines of appendChild. React's value is
 *      in managing complex interactive state, and there is none here — the data is read-only
 *      and arrives from IPC.
 *   3. No bundler, no `unsafe-inline`, no dependency to keep patched inside a security-critical
 *      desktop app.
 *
 * THE XSS RULE, absolute: party names, ledger names, and company names come from a customer's
 * Tally file and are attacker-influenceable — a supplier can name themselves
 * `<img src=x onerror=...>`, and `A & B Traders <Mumbai>` is a perfectly ordinary Indian trade
 * name that an escaping bug mangles or executes. Nothing in this file uses innerHTML with data.
 * `el(tag, class, text)` and `textContent` only, and there is deliberately no helper here that
 * takes markup — a function that did would eventually be handed a party name.
 */

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  // textContent, never innerHTML. This is the entire XSS defence for the renderer.
  if (text !== undefined) node.textContent = text;
  return node;
}

export function svg(tag: string, attrs: Record<string, string> = {}): SVGElement {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  return node;
}

/**
 * Text inside an SVG. Separate from `svg()` because the content must go through `textContent`,
 * exactly like the HTML path — an axis label can be a stock group name a human typed.
 */
export function svgText(text: string, attrs: Record<string, string> = {}): SVGElement {
  const node = svg('text', attrs);
  node.textContent = text;
  return node;
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function mount(parent: Node, ...children: Array<Node | null | undefined>): void {
  for (const c of children) if (c) parent.appendChild(c);
}

/**
 * A button with its handler already attached.
 *
 * Buttons, never a clickable div: this app is used on shop-floor touchscreens and by people who
 * navigate with a keyboard, and `<button>` is what gives focus, Enter/Space and a role for free.
 */
export function button(className: string, label: string, onClick: () => void): HTMLButtonElement {
  const b = el('button', className, label);
  b.type = 'button';
  b.addEventListener('click', onClick);
  return b;
}

/**
 * Set a CSS custom property from data.
 *
 * The CSP has no 'unsafe-inline', so nothing here may build a `style="..."` attribute string;
 * this goes through the CSSOM, which CSP does not gate, and it carries a NUMBER into a variable
 * the stylesheet consumes rather than carrying CSS text. The value is always something this
 * file computed (a percentage, a pixel count) — never a string from Tally.
 */
export function setVar(node: HTMLElement | SVGElement, name: string, value: string): void {
  node.style.setProperty(name, value);
}

/**
 * Give a node an accessible name and, when it is a chart, the text a screen reader needs.
 *
 * A hand-drawn SVG is invisible to assistive tech unless it is labelled. Every chart in this
 * renderer is decorative in the strict sense — the same numbers are always present as text
 * beside it — but the label still says what the picture is.
 */
export function describe(node: Element, role: string, label: string): void {
  node.setAttribute('role', role);
  node.setAttribute('aria-label', label);
}
