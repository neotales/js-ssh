"use strict";
const { styleText } = require("util");
const process = require("process");
const filePaths = [
    "tests/keys.test.js",
    "tests/known_hosts.test.js",
    "tests/primitives.test.js",
    "tests/signature.test.js",
];
async function main() {
    const fileIndexArg = process.argv[2];
    if (fileIndexArg == null) {
        const { spawnSync } = require("child_process");
        let failed = false;
        for (const i of filePaths.keys()) {
            if (i > 0) {
                console.log("");
            }
            const args = [...process.execArgv, __filename, String(i)];
            const result = spawnSync(process.execPath, args, { stdio: "inherit" });
            if (result.error != null) {
                console.error(result.error);
            }
            if (result.status !== 0) {
                failed = true;
            }
        }
        if (failed) {
            process.exitCode = 1;
        }
        return;
    }
    const filePath = filePaths[Number(fileIndexArg)];
    if (filePath == null) {
        console.error("Unknown test file index: " + fileIndexArg);
        process.exitCode = 1;
        return;
    }
    const esmPath = "./esm/" + filePath;
    console.log("\nRunning tests in " + styleText("underline", esmPath) + "...\n");
    process.chdir(__dirname + "/esm");
    await import(esmPath);
}
main();
