// Preload for the visual harness ONLY. Not shipped, not referenced by the app.
//
// The renderer's `main.js` is a module that calls `boot()` on load, and `boot()` reads
// `window.bridge` immediately. So the stub must be installed before the first byte of the
// module runs — a preload is the only hook that is reliably earlier.
//
// `contextIsolation: false` in the harness is what lets this write to the page's real `window`.
// That is a deliberate inversion of the app's hardening and is safe here for one reason only:
// this window loads a local file, has no remote content, and exists to be lied to.
// Which stub to install is chosen by the harness through an env var rather than an argument:
// a preload gets no argv of its own.
process.once('loaded', () => {
  const screen = process.env.TB_VISUAL_SCREEN;
  const src = screen
    ? require('./visual-wizard-stub.cjs').stubFor(screen)
    : require('./visual-stub.cjs').STUB;
  // eslint-disable-next-line no-eval
  eval(src);
});
