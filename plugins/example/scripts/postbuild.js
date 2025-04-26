import fse from "fs-extra";
import fs from "fs";
import path from "path";
import archiver from "archiver";
const pkg = JSON.parse(fs.readFileSync("./package.json"));

async function run() {
    const outDir = path.resolve("out");
    const distDir = path.resolve("dist");
    const zipPath = path.join(outDir, `${pkg.name}.zip`);

    await fse.ensureDir(outDir);

    if (!(await fse.pathExists(distDir))) {
        console.error("Error: dist/ directory not found!");
        process.exit(1);
    }

    const output = fse.createWriteStream(zipPath);
    const archive = archiver("zip", { zlib: { level: 9 } });

    archive.pipe(output);
    archive.directory(distDir, false);
    await archive.finalize();
    fs.rmSync(distDir, { recursive: true, force: true });

    console.log(`Created: ${zipPath}`);
}

run().catch(console.error);
