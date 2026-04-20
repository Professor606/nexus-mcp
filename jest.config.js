/** @type {import('jest').Config} */
export default {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
  moduleNameMapper: {
    // Rewrite ".js" extension imports (TypeScript ESM convention) back to
    // their real .ts source files so Jest can find and transform them.
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        useESM: true,
        // Point to the test-specific tsconfig (see tsconfig.test.json).
        // Must use NodeNext to match the project's module resolution.
        tsconfig: "./tsconfig.test.json",
      },
    ],
  },
  testMatch: ["**/tests/**/*.test.ts"],
};
