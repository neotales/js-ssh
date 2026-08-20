const root = Deno.cwd();
const packageDirectory = `${root}/npm/ssh`;
const executableExtension = Deno.build.os === "windows" ? ".cmd" : "";
const oxfmt = `${root}/node_modules/.bin/oxfmt${executableExtension}`;
const oxlint = `${root}/node_modules/.bin/oxlint${executableExtension}`;

function usage(): never {
  console.error(`Usage: deno task <task> [--node] [--deno] [--bun]

Tasks:
  build                    Compile the npm package with TypeScript
  test [runtime flags]     Build and run available tests
  lint                     Check TypeScript with oxlint
  fmt [--check]            Format or check formatting with oxfmt
  audit                    Audit npm dependencies
  check                    Run the complete local quality gate
  pack                     Create an npm tarball
  clean                    Remove temporary test output`);
  Deno.exit(1);
}

async function run(command: string, args: string[], cwd = root): Promise<void> {
  const output = await new Deno.Command(command, {
    args,
    cwd,
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  }).output();
  if (!output.success) Deno.exit(output.code);
}

async function testFiles(directory: string): Promise<string[]> {
  const files: string[] = [];
  for await (const entry of Deno.readDir(directory)) {
    const path = `${directory}/${entry.name}`;
    if (entry.isDirectory) {
      files.push(...(await testFiles(path)));
    } else if (entry.isFile && entry.name.endsWith(".test.ts")) {
      files.push(path);
    }
  }
  return files.sort();
}

async function build(): Promise<void> {
  await run("pnpm", ["exec", "tsc", "-p", "tsconfig.json"], packageDirectory);
}

async function format(check: boolean): Promise<void> {
  await run(oxfmt, [
    check ? "--check" : "--write",
    "--ignore-path",
    ".prettierignore",
    "eng",
    "npm",
    "README.md",
    "LICENSE.md",
    "deno.json",
    "package.json",
    "pnpm-workspace.yaml",
    ".oxlintrc.json",
    ".oxfmtrc.json",
  ]);
}

async function lint(): Promise<void> {
  await run(oxlint, [
    "--ignore-pattern",
    "npm/*/esm/**",
    "--ignore-pattern",
    "npm/*/types/**",
    "npm",
    "eng",
  ]);
}

async function test(runtimes: Set<string>): Promise<void> {
  await build();
  const files = await testFiles(`${packageDirectory}/tests`);
  if (!files.length) {
    console.log("No test files found.");
    return;
  }

  const selected = runtimes.size ? runtimes : new Set(["node", "deno", "bun"]);
  if (selected.has("deno")) await run("deno", ["test", "-A", ...files], packageDirectory);
  if (selected.has("node")) {
    await run("pnpm", ["exec", "tsc", "-p", "tsconfig.test.json"], packageDirectory);
    const compiled = files.map((file) =>
      file.replace(/\.ts$/, ".js").replace("/tests/", "/.test/tests/"),
    );
    await run("node", ["--test", ...compiled], packageDirectory);
  }
  if (selected.has("bun")) await run("bun", ["test", ...files], packageDirectory);
}

async function clean(): Promise<void> {
  await Deno.remove(`${packageDirectory}/.test`, { recursive: true }).catch((error: unknown) => {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  });
}

const [command, ...args] = Deno.args;
const runtimes = new Set(args.filter((arg) => arg.startsWith("--")).map((arg) => arg.slice(2)));
const unknownRuntimes = [...runtimes].filter(
  (runtime) => !["node", "deno", "bun", "check"].includes(runtime),
);
if (unknownRuntimes.length) usage();

switch (command) {
  case "build":
    await build();
    break;
  case "test":
    await test(runtimes);
    break;
  case "lint":
    await lint();
    break;
  case "fmt":
    await format(args.includes("--check"));
    break;
  case "audit":
    await run("pnpm", ["audit", "--audit-level", "moderate"]);
    break;
  case "check":
    await lint();
    await format(true);
    await run("pnpm", ["audit", "--audit-level", "moderate"]);
    await test(new Set());
    break;
  case "pack":
    await build();
    await run("pnpm", ["pack"], packageDirectory);
    break;
  case "clean":
    await clean();
    break;
  default:
    usage();
}
