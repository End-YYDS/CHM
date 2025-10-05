const {execSync} = require("child_process");
if (process.argv[4] === "1") {
  console.log("Cleaning up untracked & ignored files via git clean -fd...");
  try {
    execSync('git clean -fd -e "certs/*"', {stdio: "inherit"});
    console.log("Cleanup completed.");
  } catch (err) {
    console.error("git clean 失敗", err.message);
    process.exit(1);
  }
} else {
  console.log("No branch switch detected. Skipping cleanup.");
}
