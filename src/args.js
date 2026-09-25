// CLI argument parsing. Pure, zero-I/O logic extracted from bin/riskcard.js
// so it's unit testable without spawning a subprocess. Throws a plain Error
// on an unknown/invalid argument rather than calling process.exit itself --
// the CLI entrypoint owns turning that into an exit code.

export function parseArgs(argv) {
  const args = { in: null, out: null, format: "md", config: null, help: false, version: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--in") args.in = argv[++i];
    else if (a === "--out") args.out = argv[++i];
    else if (a === "--format") args.format = argv[++i];
    else if (a === "--config") args.config = argv[++i];
    else if (a === "-h" || a === "--help") args.help = true;
    else if (a === "-v" || a === "--version") args.version = true;
    else throw new Error(`Unknown argument: ${a}`);
  }
  if (args.format !== "md" && args.format !== "json") {
    throw new Error(`--format must be "md" or "json", got "${args.format}"`);
  }
  return args;
}
