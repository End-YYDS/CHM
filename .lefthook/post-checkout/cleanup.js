const fs = require("fs");
const path = require("path");
console.log(process.argv);

if (process.argv[4] === "1") {
  console.log("Cleaning up build artifacts and dependencies...");

  const targetDir = path.join(process.cwd(), "target");
  if (fs.existsSync(targetDir)) {
    console.log("Removing Rust target directory...");
    fs.rmSync(targetDir, { recursive: true, force: true });
  }

  const nodeModulesDir = path.join(process.cwd(), "frontend", "node_modules");
  if (fs.existsSync(nodeModulesDir)) {
    console.log("Removing pnpm node_modules directory...");
    fs.rmSync(nodeModulesDir, { recursive: true, force: true });
  }
  console.log("Cleanup completed.");
} else {
  console.log("No branch switch detected. Skipping cleanup.");
}
