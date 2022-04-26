const assert = require("assert");
const esutils = require("esutils");
const {keyword: {isIdentifierES6, isIdentifierNameES6}} = esutils;

const { testRepeatedly, prng } = require("./helpers");
const { fuzzProgram, FuzzerState, fuzzIdentifier, fuzzWhileStatement } = require("../");
const fuzzRegExpPattern = require("../src/regexp");

suite("unit", () => {
  testRepeatedly("fuzzIdentifier produces a valid Identifier (not IdentifierName)", () => {
    for (let i = 0; i < 30e3; ++i) {
      let ident = fuzzIdentifier();
      try {
        if (ident === 'enum') continue;
        assert(isIdentifierNameES6(ident));
        assert(isIdentifierES6(ident));
      } catch(e) {
        console.log(ident);
      }
    }
  });

  testRepeatedly("fuzzXXX takes a FuzzerState to allow seeded rng configuration", () => {
    prng.reset();
    let identA = fuzzIdentifier(new FuzzerState({rng: prng})).name;
    prng.reset();
    let identB = fuzzIdentifier(new FuzzerState({rng: prng})).name;
    assert.equal(identA, identB);

    prng.reset();
    let programA = fuzzProgram(new FuzzerState({rng: prng}));
    prng.reset();
    let programB = fuzzProgram(new FuzzerState({rng: prng}));
    assert.deepEqual(programA, programB);
  });
  
  testRepeatedly("fuzzRegExpPattern generates valid regexp", () => {
    let expression = fuzzRegExpPattern(new FuzzerState());
    let flags = [
      expression.global ? 'g' : '',
      expression.ignoreCase ? 'i' : '',
      expression.multiline ? 'm' : '',
      expression.sticky ? 'y' : '',
      expression.unicode ? 'u' : ''
    ].join('');
    try {
      RegExp(expression.pattern, flags);
    } catch (e) {
      throw new Error(`regexp failed: /${expression.pattern}/${flags} error: ${e}`);
    }
  });

  function assertDepthNoGreaterThan(n, ancestry, node) {
    if (node == null) return;
    if (typeof node.type === "string") return;
    if (n == 0) throw new Error("too deep!");
    ancestry = ancestry.concat(node.type);
    for (let prop in node) assertDepthNoGreaterThan(n - 1, ancestry, node[prop]);
  }

  testRepeatedly("fuzzXXX takes a FuzzerState to allow maximum depth configuration", () => {
    for (let depth = 1; depth < 9; ++depth) {
      let program = fuzzProgram(new FuzzerState({maxDepth: depth}));
      try {
        assertDepthNoGreaterThan(depth + 1, [], program);
      } catch(e) {
        console.log(JSON.stringify(program));
        throw e;
      }
      let whileStatement = fuzzWhileStatement(new FuzzerState({maxDepth: depth}));
      try {
        assertDepthNoGreaterThan(depth + 1, [], whileStatement);
      } catch(e) {
        console.log(JSON.stringify(whileStatement));
        throw e;
      }
    }
  });
});
