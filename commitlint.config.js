// An ES module, because package.json's "type": "module" makes every .js file
// here one (the TypeScript port's): `module.exports` would fail to load, and
// the commit-msg hook with it.
export default { extends: ["@commitlint/config-conventional"] };
