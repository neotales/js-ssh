import { build as dntBuild, type EntryPoint } from "@deno/dnt";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const workspace = dirname(root);
const sourceDirectory = join(workspace, "jsr", "ssh");
const packageDirectory = join(workspace, "npm", "ssh");
const executableExtension = Deno.build.os === "windows" ? ".cmd" : "";
const oxlint = join(workspace, "node_modules", ".bin", `oxlint${executableExtension}`);

type DenoPackage = {
  name: string;
  version: string;
  description: string;
  license: string;
  exports: Record<string, string>;
};

function usage(): never {
  console.error(`Usage: deno task <task> [--node] [--deno] [--bun]

Tasks:
  build                    Generate the npm package with dnt
  test [runtime flags]     Run SSH tests in selected runtimes
  lint                     Check TypeScript with oxlint
  fmt [--check]            Format or check formatting with deno fmt
  audit                    Audit npm dependencies
  check                    Run the complete local quality gate
  pack                     Generate and pack the npm package
  clean                    Remove temporary test and package artifacts`);
  Deno.exit(1);
}

async function run(command: string, args: string[], cwd = workspace): Promise<void> {
  const output = await new Deno.Command(command, {
    args,
    cwd,
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  }).output();
  if (!output.success) Deno.exit(output.code);
}

async function packageConfig(): Promise<DenoPackage> {
  return JSON.parse(await Deno.readTextFile(join(sourceDirectory, "deno.json"))) as DenoPackage;
}

async function build(testBun = false): Promise<void> {
  const config = await packageConfig();
  const entryPoints: EntryPoint[] = Object.entries(config.exports).map(([name, path]) => ({
    name,
    path: join(sourceDirectory, path),
  }));
  const artifactsDirectory = join(workspace, "artifacts");
  await Deno.mkdir(artifactsDirectory, { recursive: true });
  const outputDirectory = await Deno.makeTempDir({
    dir: artifactsDirectory,
    prefix: "npm-ssh-",
  });
  await Deno.writeTextFile(join(outputDirectory, "pnpm-workspace.yaml"), "packages: []\n");

  try {
    await dntBuild({
      entryPoints,
      outDir: outputDirectory,
      rootTestDir: join(sourceDirectory, "tests"),
      configFile: import.meta.resolve("../deno.json"),
      frozenLockfile: true,
      packageManager: "pnpm",
      scriptModule: false,
      esModule: true,
      declaration: "separate",
      skipSourceOutput: true,
      polyfills: false,
      shims: { deno: { test: "dev" } },
      test: true,
      testIsolation: "process",
      compilerOptions: {
        target: "ES2022",
        lib: ["ES2022", "DOM"],
      },
      package: {
        name: config.name,
        version: config.version,
        description: config.description,
        keywords: ["scp", "sftp", "ssh", "ssh2"],
        license: config.license,
        type: "module",
        repository: {
          type: "git",
          url: "git+https://github.com/neotales/js-ssh.git",
        },
        bugs: { url: "https://github.com/neotales/js-ssh/issues" },
        homepage: "https://github.com/neotales/js-ssh",
        engines: { node: ">=22" },
      },
      postBuild() {
        Deno.copyFileSync(join(sourceDirectory, "README.md"), join(outputDirectory, "README.md"));
        Deno.copyFileSync(join(workspace, "LICENSE.md"), join(outputDirectory, "LICENSE.md"));
      },
    });
    if (testBun) await run("bun", ["test_runner.cjs"], outputDirectory);

    for (const name of ["node_modules", "pnpm-lock.yaml", "pnpm-workspace.yaml"]) {
      await Deno.remove(join(outputDirectory, name), { recursive: true }).catch(
        (error: unknown) => {
          if (!(error instanceof Deno.errors.NotFound)) throw error;
        },
      );
    }
    await Deno.remove(packageDirectory, { recursive: true });
    await Deno.rename(outputDirectory, packageDirectory);
  } finally {
    await Deno.remove(outputDirectory, { recursive: true }).catch((error: unknown) => {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    });
  }
}

async function format(check: boolean): Promise<void> {
  await run("deno", [
    "fmt",
    ...(check ? ["--check"] : []),
    "--config",
    join(workspace, "deno.json"),
    "eng",
    "jsr",
    ".github",
    ".vscode",
    "README.md",
    "LICENSE.md",
    "deno.json",
    "package.json",
    "pnpm-workspace.yaml",
    ".oxlintrc.json",
  ]);
}

async function lint(): Promise<void> {
  await run(oxlint, [
    "--ignore-pattern",
    "npm/*/esm/**",
    "--ignore-pattern",
    "npm/*/types/**",
    "--ignore-pattern",
    "npm/*/esm/tests/**",
    "--ignore-pattern",
    "npm/*/esm/_dnt.test_shims.js",
    "--ignore-pattern",
    "npm/*/test_runner.*",
    "jsr",
    "npm",
    "eng",
  ]);
}

async function test(runtimes: Set<string>): Promise<void> {
  const selected = runtimes.size ? runtimes : new Set(["deno", "node"]);
  if (selected.has("deno")) await run("deno", ["test", "-A"], sourceDirectory);
  if (selected.has("node") || selected.has("bun")) await build(selected.has("bun"));
}

async function clean(): Promise<void> {
  await Deno.remove(join(packageDirectory, "node_modules"), { recursive: true }).catch(
    (error: unknown) => {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    },
  );
  for await (const entry of Deno.readDir(packageDirectory)) {
    if (entry.isFile && entry.name.endsWith(".tgz")) {
      await Deno.remove(join(packageDirectory, entry.name));
    }
  }
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
