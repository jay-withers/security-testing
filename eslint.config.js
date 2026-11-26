import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["coverage/", "node_modules/", ".venv/", "terraform/", "zap-wrk/"],
  },
  js.configs.recommended,
  tseslint.configs.recommended,
);
