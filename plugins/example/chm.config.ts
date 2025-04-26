import { name } from "./package.json";
const federationExposes = {
    "./App": "./src/App.tsx",
};
let host = process.env.BACKEND || "http://localhost:8080";
host = host.endsWith("/") ? host : `${host}/`;
let base = host + "static/plugins/";
let backend = base + `${name}/`;
let api = host + `api/plugin/${name}/`;

export { federationExposes, backend, api };
