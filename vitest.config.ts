import { defineConfig } from "vitest/config";

// Cobertura is the report workflows' node.yml reads for both coverage floors;
// text is for the terminal.
export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      // The wiring that only builds Azure SDK clients, untested on purpose
      // (see the comment at the top of azure.ts).
      exclude: ["src/azure.ts", "src/main.ts"],
      reporter: ["text", "cobertura"],
    },
  },
});
