import { defineConfig, Plugin, ResolvedConfig } from "vite";
import react from "@vitejs/plugin-react";
import fs from "fs";
import path from "path";
import tailwindcss from "@tailwindcss/vite";
import { federation } from "@module-federation/vite";
import { name, dependencies, version, description } from "./package.json";
import { federationExposes, backend } from "./chm.config";

function injectInfoAfterBuild(): Plugin {
    let finalJS = "";
    let finalCSS = "";
    let outDir = "";
    const exposeKey = Object.keys(federationExposes)[0];
    return {
        name: "inject-info-after-build",
        configResolved(resolvedConfig: ResolvedConfig) {
            outDir = resolvedConfig.build.outDir;
        },
        generateBundle(_, bundle) {
            let _name = name + ".js";
            for (const [fileName] of Object.entries(bundle)) {
                if (fileName.endsWith(".js") && fileName === _name) {
                    finalJS = fileName;
                }
                if (fileName.endsWith(".css")) {
                    finalCSS = fileName;
                }
            }
        },
        closeBundle() {
            const luaPath = path.resolve(__dirname, "public/info.lua");
            let content = fs.readFileSync(luaPath, "utf-8");
            content = content
                .replace(/name\s*=\s*".*?"/, `name = "${name}"`)
                .replace(
                    /description\s*=\s*".*?"/,
                    `description = "${description || ""}"`
                )
                .replace(/version\s*=\s*".*?"/, `version = "${version}"`)
                .replace(/mainFile\s*=\s*".*?"/, `mainFile = "${finalJS}"`)
                .replace(/cssFile\s*=\s*".*?"/, `cssFile = "${finalCSS}"`)
                .replace(
                    /exportName\s*=\s*".*?"/,
                    `exportName = "${exposeKey}"`
                );
            fs.writeFileSync(luaPath, content);
            console.log(
                `info.lua 已更新:
  name = ${name},
  version = ${version},
  mainFile = ${finalJS},
  cssFile = ${finalCSS},
  exportName = ${exposeKey}`
            );
            const outDirectory = path.resolve(__dirname, outDir);

            const outLuaPath = path.join(outDirectory, "info.lua");
            fs.copyFileSync(luaPath, outLuaPath);

            const indexHtmlPath = path.join(outDirectory, "index.html");
            if (fs.existsSync(indexHtmlPath)) {
                fs.unlinkSync(indexHtmlPath);
            }
        },
    };
}

// https://vite.dev/config/
export default defineConfig({
    base: backend,
    plugins: [
        react(),
        injectInfoAfterBuild(),
        tailwindcss(),
        federation({
            name: `${name}`,
            filename: `${name}.js`,
            exposes: federationExposes,
            shared: {
                react: {
                    singleton: true,
                    requiredVersion: dependencies["react"],
                },
                "react-dom": {
                    singleton: true,
                    requiredVersion: dependencies["react-dom"],
                },
            },
        }),
    ],
    build: {
        target: "esnext",
        emptyOutDir: true,
        outDir: "dist",
    },
    define: {
        "process.env": {},
    },
    server: {
        host: "localhost",
        port: 5174,
        cors: true,
    },
    resolve: {
        alias: {
            "@": path.resolve(__dirname, "./src"),
        },
    },
});
